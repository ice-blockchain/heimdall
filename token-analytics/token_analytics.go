// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	stdlog "log"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/heimdall/token-analytics/ddl"
	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/cdn"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/llm"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	appconfig "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

func TokenizedCommunitiesBondingCurveSmartContractABI() string {
	return bondingcurve.ABIJSON
}

func NewUserRepository(ctx context.Context) interface {
	UserRepository
	PriceSync
} {
	var cfg config
	var development bool

	appconfig.MustLoadFromKey("development", &development)
	if !development {
		log.Info("running in production mode, TA UserRepository is disabled")
		return new(dummyUserRepository)
	}

	appconfig.MustLoadFromKey(applicationYamlKey, &cfg)
	db := storage.MustConnect(ctx, applicationYamlKey, storage.NewFilesystemDDL(&ddl.Files, schemeMigrationTableName))

	return &tokenAnalyticsUsers{
		ingestedDataDB: db,
		cfg:            &cfg,
		shutdown: func() error {
			return errors.Join(
				db.Close(),
			)
		},
	}
}

func New(ctx context.Context, coinImport CoinImport) TokenAnalytics {
	var cfg config

	appconfig.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.Workers == 0 {
		cfg.Workers = 1
	}
	if cfg.BondingCurve.BurnAddress == "" {
		cfg.BondingCurve.BurnAddress = "0x0000000000000000000000000000000000696f6e"
	}

	db := storage.MustConnect(ctx, applicationYamlKey, storage.NewFilesystemDDL(&ddl.Files, schemeMigrationTableName))
	targetDB := storagev3.MustConnect(ctx, applicationYamlKey)
	if err := initializeWorkersConfig(ctx, db, cfg.Workers); err != nil {
		log.Panic(fmt.Errorf("failed to initialize workers config: %w", err))
	}

	questDB := questdb.MustConnect(ctx, applicationYamlKey)
	registry := metrics.NewRegistry()
	for workerIdx := range cfg.Workers {
		workerPrefix := fmt.Sprintf("worker_%d_", workerIdx)
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"iteration",
			metrics.NewCustomTimer(metrics.NewHistogram(metrics.NewExpDecaySample(10_000, 0.015)), metrics.NewMeter())),
			"failed to register worker %d iteration timer", workerIdx))
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"tx_to_process_fetch",
			metrics.NewCustomTimer(metrics.NewHistogram(metrics.NewExpDecaySample(10_000, 0.015)), metrics.NewMeter())),
			"failed to register worker %d tx_to_process_fetch", workerIdx))
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"events_processed", metrics.NewMeter()),
			"failed to register worker %d events meter", workerIdx))
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"errors", metrics.NewMeter()),
			"failed to register worker %d errors meter", workerIdx))
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"block_number", metrics.NewGauge()),
			"failed to register worker %d block_number gauge", workerIdx))
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"transaction_index", metrics.NewGauge()),
			"failed to register worker %d transaction_index gauge", workerIdx))
	}
	log.Panic(errors.Wrapf(registry.Register("stream_creator_iterations", metrics.NewMeter()),
		"failed to register stream creator iterations meter"))

	bc := bondingcurve.New(ctx, applicationYamlKey)

	if cfg.RiverQueue.QueueName == "" {
		cfg.RiverQueue.QueueName = "heimdall_ta"
	}
	if cfg.RiverQueue.MaxQueueWorkers == 0 {
		cfg.RiverQueue.MaxQueueWorkers = 100
	}
	if cfg.RiverQueue.JobMaxTimeout == 0 {
		cfg.RiverQueue.JobMaxTimeout = 30 * stdlibtime.Second
	}
	riverCfg := riverqueue.Config{
		QueueName:       cfg.RiverQueue.QueueName,
		MaxQueueWorkers: cfg.RiverQueue.MaxQueueWorkers,
		JobMaxTimeout:   cfg.RiverQueue.JobMaxTimeout,
		Credentials:     cfg.Storage.Credentials,
		PrimaryURLs:     append([]string{cfg.Storage.PrimaryURL}, cfg.Storage.PrimaryFallbackURLs...),
	}

	riverClient := riverqueue.MustNewClient(ctx,
		applicationYamlKey,
		riverqueue.WithConfig(&riverCfg))

	t := &tokenAnalytics{
		bondingCurveContractAddress: cfg.BondingCurve.SmartContractAddress,
		tokenFactoryContractAddress: cfg.BondingCurve.TokenFactorySmartContractAddress,
		ingestedDataDB:              db,
		processedDataDB:             targetDB,
		questDB:                     questDB,
		wg:                          new(sync.WaitGroup),
		cfg:                         &cfg,
		metrics:                     registry,
		bondingCurve:                bc,
		riverClient:                 riverClient,
		ohclvRecentData:             xsync.NewMap[string, *recentCandlestick](),
		tradingStatsRecentData:      xsync.NewMap[string, *recentTradeStats](),
		subscriptions:               newSubscriptions(ctx),
		identityClient:              newIdentityClient(cfg.IdentityServiceURL, cfg.IdentityServiceAPIKey),
		llmClient:                   llm.New(cfg.LLM),
		coins:                       coinImport,
		creatorTokenPricesUSD:       xsync.NewMap[string, float64](),
		shutdown: func() error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return errors.Join(
				errors.Wrapf(riverClient.Stop(shutdownCtx), "failed to stop river queue"),
				errors.Wrapf(db.Close(), "failed to close source db"),
				errors.Wrapf(targetDB.Close(), "failed to close target db"),
				errors.Wrapf(questDB.Close(shutdownCtx), "failed to close questdb"),
			)
		},
	}

	t.cdnClient = cdn.New(ctx, &cfg.CDN, riverClient, cdn.WithObserver(t))
	if reg := riverClient.Register(); reg != nil {
		riverqueue.RegisterWorker(reg, &balanceUpdateWorker{
			bondingCurve:    bc,
			ingestedDataDB:  db,
			processedDataDB: targetDB,
			ta:              t,
		})
		riverqueue.RegisterWorker(reg, &tokenDetailsGenerationPictureWorker{
			TA: t,
		})
	}

	t.ionPriceUSD = new(atomic.Pointer[float64])
	t.bnbPriceUSD = new(atomic.Pointer[float64])
	go metrics.LogScaled(registry, 5*stdlibtime.Minute, 1*stdlibtime.Second, t)
	if err := t.syncIONPrice(ctx); err != nil && !storage.IsErr(err, storage.ErrReadOnly) && !errors.Is(err, context.Canceled) {
		log.Panic(errors.Wrapf(err, "failed to sync ion price on startup"))
	}
	if err := t.loadBNBPrice(ctx); err != nil && !storage.IsErr(err, storage.ErrReadOnly) && !errors.Is(err, context.Canceled) {
		log.Panic(errors.Wrapf(err, "failed to load bnb price on startup"))
	}

	go t.startIONPriceSyncer(ctx)
	go t.startBNBPriceLoader(ctx)
	t.startBondingCurveNotifier(ctx)
	t.startUserBalanceNotifier(ctx)

	if err := riverClient.Start(ctx); err != nil {
		log.Panic(errors.Wrap(err, "failed to start river queue"))
	}

	if cfg.EnableDummyGenerator {
		log.Info("Dummy data generator is ENABLED")
		startLastBlock, err := t.getDummySavePoint(ctx, 0)
		if err != nil {
			log.Panic(errors.Wrapf(err, "failed to get save point for dummy generator"))
		}
		savePointMap := xsync.NewMap[uint, *SavePoint]()
		savePointMap.Store(0, &SavePoint{BlockNumber: startLastBlock.BlockNumber, TransactionIndex: 0})
		t.generator = &dummyDataGenerator{
			Target:                      db,
			IONTokenAddress:             cfg.IONTokenAddress,
			InsertBlockIndex:            startLastBlock.BlockNumber,
			Stream:                      dummyDataStream,
			BondingCurveContractAddress: t.bondingCurveContractAddress,
			TokenFactoryContractAddress: t.tokenFactoryContractAddress,
			SavePoint:                   savePointMap,
		}
		t.generator.Run(ctx)
	} else {
		log.Info("Dummy data generator is DISABLED")
	}
	return t
}

func (t *tokenAnalytics) Close() error {
	t.wg.Wait()
	log.Info("all workers stopped")

	return t.shutdown()
}

func (t *tokenAnalyticsUsers) HealthCheck(ctx context.Context) error {
	if err := t.ingestedDataDB.Ping(ctx); err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
		return fmt.Errorf("database connection failed: %w", err)
	}

	return nil
}

func (t *tokenAnalyticsUsers) Close() error {
	return t.shutdown()
}

func (t *tokenAnalytics) HealthCheck(ctx context.Context) error {
	checkers := map[string]func(context.Context) error{
		"ingested_datatabase": func(ctx context.Context) error { return t.ingestedDataDB.Ping(ctx) },
		"processed_database":  func(ctx context.Context) error { return t.processedDataDB.Ping(ctx).Err() },
		"questdb_database":    t.questDB.Ping,
	}

	for name, checker := range checkers {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := checker(ctxWithTimeout)
		cancel()
		if err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
			return fmt.Errorf("%s: check failed: %w", name, err)
		}
	}
	return nil
}

func (t *tokenAnalyticsUsers) UpsertUser(ctx context.Context, id, masterPubkey, blockchainAddress, username, displayName, avatar string, verified *bool, ionConnectRelays []string) error {
	lookup := strings.ToLower(strings.TrimSpace(username + " " + displayName))
	externalAddress := BuildProfileExternalAddress(masterPubkey)
	verifiedVal := false
	if verified != nil {
		verifiedVal = *verified
	}
	relays := ionConnectRelays
	if relays == nil {
		relays = []string{}
	}

	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, content_author_id, external_address, username, 
			display_name, avatar, lookup, ion_connect_relays, verified, platform_group
		) VALUES (
			NOW(), NOW(), $1, $2, $10, $9, $3, $4, $5, $6, $7, $8, 'ionconnect'::platform_type
		)
		ON CONFLICT (content_author_id) 
		DO UPDATE SET
			updated_at = NOW(),
			id = EXCLUDED.id,
			master_pubkey = EXCLUDED.master_pubkey,
			external_address = EXCLUDED.external_address,
			username = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name),
			avatar = COALESCE(NULLIF(EXCLUDED.avatar, ''), users.avatar),
			lookup = CASE 
				WHEN EXCLUDED.username != '' OR EXCLUDED.display_name != '' THEN 
					LOWER(TRIM(COALESCE(NULLIF(EXCLUDED.username, ''), users.username) || ' ' || COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name)))
				ELSE users.lookup
			END,
			ion_connect_relays = CASE WHEN $11 THEN EXCLUDED.ion_connect_relays ELSE users.ion_connect_relays END,
			verified = CASE WHEN $11 THEN EXCLUDED.verified ELSE users.verified END,
			platform_group = EXCLUDED.platform_group
	`, id, masterPubkey, username, displayName, avatar, lookup, relays, verifiedVal, externalAddress, blockchainAddress, verified != nil && ionConnectRelays != nil)

	log.Error(fmt.Errorf("failed to upsert user %v: %w", masterPubkey, err))
	// TODO: return an error here later.
	return nil

}

func (t *tokenAnalyticsUsers) SetVerified(ctx context.Context, masterPubkey string) error {
	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		UPDATE users 
		SET verified = true, updated_at = NOW()
		WHERE master_pubkey = $1
	`, masterPubkey)
	if err == nil {
		return nil
	}

	log.Error(fmt.Errorf("failed to set verified for user %v: %w", masterPubkey, err))
	// TODO: return an error here later.
	return nil
}

func (t *tokenAnalyticsUsers) UpdateUserProfileAndToken(ctx context.Context, masterPubkey, username, displayName, avatar string) error {
	profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		WITH user_update AS (
			UPDATE users
			SET 
				username = $2,
				display_name = $3,
				avatar = CASE WHEN $4 != '' THEN $4 ELSE avatar END,
				lookup = LOWER(TRIM($2 || ' ' || COALESCE($3, ''))),
				updated_at = NOW()
			WHERE master_pubkey = $1
			RETURNING 1
		)
		UPDATE tokens
		SET 
			ticker = $2,
			title = $3,
			image_url = CASE WHEN $4 != '' THEN $4 ELSE image_url END,
			lookup = LOWER(TRIM(
				COALESCE(contract_address, '') || ' ' ||
				COALESCE($2, '') || ' ' ||
				COALESCE($3, '')
			)),
			updated_at = NOW()
		FROM user_update
		WHERE tokens.external_address = $5 
			AND tokens.type = 'profile'
	`, masterPubkey, username, displayName, avatar, profileExternalAddr)

	if err != nil {
		log.Error(fmt.Errorf("failed to update user profile and token: %w", err))
	}

	// TODO: return an error here later.
	return nil
}

func (t *tokenAnalyticsUsers) GetUser(ctx context.Context, masterPubkey string) (*UserRecord, error) {
	user, err := storage.Get[UserRecord](ctx, t.ingestedDataDB,
		`SELECT id, master_pubkey, content_author_id, external_address, username, 
		        display_name, avatar, lookup, ion_connect_relays, verified, platform_group 
		 FROM users WHERE master_pubkey = $1`, masterPubkey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, nil
		}

		return nil, errors.Wrap(err, "failed to get user")
	}
	return user, nil
}

func (t *tokenAnalytics) MustStart(ctx context.Context) {
	for workerIdx := range t.cfg.Workers {
		t.wg.Go(func() {
			t.runEventsProcessor(ctx, workerIdx)
		})
	}

	go t.runMaterializedViewRefreshWorker(ctx)
	go t.runVolumeWorker(ctx)
}

func (t *tokenAnalytics) runEventsProcessor(ctx context.Context, workerIdx uint) {
	workerPrefix := fmt.Sprintf("worker_%d_", workerIdx)
	iterationTimer := t.metrics.Get(workerPrefix + "iteration").(metrics.Timer)
	txFetcherTimer := t.metrics.Get(workerPrefix + "tx_to_process_fetch").(metrics.Timer)
	eventsProcessed := t.metrics.Get(workerPrefix + "events_processed").(metrics.Meter)
	errorsMeter := t.metrics.Get(workerPrefix + "errors").(metrics.Meter)
	blockGauge := t.metrics.Get(workerPrefix + "block_number").(metrics.Gauge)
	transactionGauge := t.metrics.Get(workerPrefix + "transaction_index").(metrics.Gauge)

	var (
		eventsToProcess = make([]*txEvent, 0, t.cfg.BatchSize)
		err             error
	)
	startPoint, err := t.getSavePoint(ctx, workerIdx)
	if err != nil {
		log.Panic(fmt.Errorf("failed to get save point for worker %d: %w", workerIdx, err))
	}
	dummyStartPoint, err := t.getDummySavePoint(ctx, workerIdx)
	if err != nil {
		log.Panic(fmt.Errorf("failed to get dummy save point for worker %d: %w", workerIdx, err))
	}
	log.Info(fmt.Sprintf("Worker %d started from block %d (dummy: %d)", workerIdx, startPoint.BlockNumber, dummyStartPoint.BlockNumber))

	resetVars := func(success bool) {
		if !success {
			time.Sleep(1 * time.Second)
			errorsMeter.Mark(1)
		}
		eventsToProcess = eventsToProcess[:0]
	}
	for ctx.Err() == nil {
		iterationStart := time.Now()
		iterationCtx, iterationCancel := context.WithTimeout(ctx, 30*time.Second)
		fetchStart := time.Now()
		eventsToProcess, err = t.fetchUnprocessedEvents(iterationCtx, workerIdx, startPoint, dummyStartPoint)
		if err != nil {
			log.Error(fmt.Errorf("[worker %d] failed to fetch new tx events: %w", workerIdx, err))
			iterationCancel()
			resetVars(false)

			continue
		}
		fetchDuration := time.Since(fetchStart)
		txFetcherTimer.Update(fetchDuration)
		if len(eventsToProcess) == 0 {
			time.Sleep(1 * time.Second)
			iterationCancel()

			continue
		}
		hasNonDummyData := false
		hasDummyData := false
		for _, tx := range eventsToProcess {
			isDummyTx := tx.Dummy
			if isDummyTx {
				hasDummyData = true
			} else {
				hasNonDummyData = true
			}

			for _, logEvent := range tx.Logs {
				if err = t.processLog(iterationCtx, tx, &logEvent); err != nil {
					log.Error(fmt.Errorf("[worker %d] failed to process log %+v in tx %v: %w", workerIdx, logEvent, tx.TransactionHash, err))
					errorsMeter.Mark(1)

					continue
				}
				eventsProcessed.Mark(1)
			}
			if isDummyTx {
				if tx.BlockNumber > dummyStartPoint.BlockNumber {
					dummyStartPoint.BlockNumber = tx.BlockNumber
					dummyStartPoint.TransactionIndex = tx.TransactionIndex
					dummyStartPoint.BlockTime = tx.BlockTimestamp.Time.Unix()
				} else if tx.BlockNumber == dummyStartPoint.BlockNumber && tx.TransactionIndex > dummyStartPoint.TransactionIndex {
					dummyStartPoint.TransactionIndex = tx.TransactionIndex
				}
			} else {
				if tx.BlockNumber > startPoint.BlockNumber {
					startPoint.BlockNumber = tx.BlockNumber
					startPoint.TransactionIndex = tx.TransactionIndex
					startPoint.BlockTime = tx.BlockTimestamp.Time.Unix()
					blockGauge.Update(int64(tx.BlockNumber))
				} else if tx.BlockNumber == startPoint.BlockNumber && tx.TransactionIndex > startPoint.TransactionIndex {
					startPoint.TransactionIndex = tx.TransactionIndex
				}
			}
			transactionGauge.Update(int64(tx.TransactionIndex))
		}
		if hasDummyData && t.generator != nil && t.generator.SavePoint != nil {
			t.generator.SavePoint.Store(workerIdx, &SavePoint{BlockNumber: dummyStartPoint.BlockNumber, TransactionIndex: dummyStartPoint.TransactionIndex})
		}
		if hasNonDummyData {
			if err = t.setSavePoint(iterationCtx, workerIdx, startPoint); err != nil {
				log.Error(fmt.Errorf("[worker %d] failed to save point: %w", workerIdx, err))
				resetVars(false)
				iterationCancel()

				continue
			}
		}
		if hasDummyData {
			if err = t.setDummySavePoint(iterationCtx, workerIdx, dummyStartPoint); err != nil {
				log.Error(fmt.Errorf("[worker %d] failed to save dummy point: %w", workerIdx, err))
				resetVars(false)
				iterationCancel()

				continue
			}
		}

		iterationCancel()
		iterationDuration := time.Since(iterationStart)
		iterationTimer.Update(iterationDuration)
		resetVars(true)
	}

	log.Info(fmt.Sprintf("[worker %d] stopped", workerIdx))
}

func (t *tokenAnalytics) processLog(ctx context.Context, tx *txEvent, logEvent *JSON) error {
	topic0, _ := logEvent.getString("topic0")
	data, _ := logEvent.getString("data")
	topics, _ := logEvent.getStringSlice("topics")
	address, _ := logEvent.getString("address")

	parsedEv, err := bondingcurve.ProcessEvent(topic0, data, topics, address, tx.Input)
	if err != nil {
		log.Error(fmt.Errorf("failed to process event topic0=%s, address=%s, data=%s: %w", topic0, address, data, err))
		return err
	}

	switch ev := parsedEv.(type) {
	case *bondingcurve.LogTokenCreated:
		return t.onTokenCreated(ctx, address, ev)
	case *bondingcurve.LogTokenSwapped:
		return t.onSwap(ctx, tx, ev)
	case *bondingcurve.LogPairRegistered:
		return t.onPairRegistered(ctx, tx, ev)
	case *bondingcurve.LogRecipientsSet:
		return t.onRecipientsSet(ctx, tx, ev)
	case *bondingcurve.LogMigrated:
		return t.onMigrated(ctx, tx, ev)
	case *bondingcurve.LogFeeAccrued:
		return t.onFeeAccrued(ctx, tx, ev)
	case *bondingcurve.LogFeeTransfer:
		return t.onFeeTransfer(ctx, tx, ev)
	case *bondingcurve.LogFeeWaived:
		return t.onFeeWaived(ctx, tx, ev)
	case *bondingcurve.LogLiquidityClaimed:
		return t.onLiquidityClaimed(ctx, tx, ev)
	case *bondingcurve.LogSlippageChecked:
		return t.onSlippageChecked(ctx, tx, ev)
	case *bondingcurve.LogLiquidityLocked:
		return t.onLiquidityLocked(ctx, tx, ev)
	case *bondingcurve.LogRefundIssued:
		return t.onRefundIssued(ctx, tx, ev)
	case *bondingcurve.LogRouteSelected:
		return t.onRouteSelected(ctx, tx, ev)
	case *bondingcurve.LogVerificationChecked:
		return t.onVerificationChecked(ctx, tx, ev)
	case *bondingcurve.LogUniswapSwapped:
		return t.onUniswapSwapped(ctx, tx, ev)
	case *bondingcurve.LogPoolCreated:
		return t.onUniswapPoolCreated(ctx, tx, ev)
	case *bondingcurve.LogTransfer:
		return t.onTransfer(ctx, tx, ev)
	}

	return nil
}

func (t *tokenAnalytics) Printf(format string, args ...interface{}) {
	stdlog.Printf(format, args...)
}

func (t *tokenAnalytics) fetchUnprocessedEvents(ctx context.Context, workerIdx uint, start *SavePoint, dummyStart *SavePoint) ([]*txEvent, error) {
	sql := fmt.Sprintf(`
		SELECT * FROM (
		SELECT 
			t.transaction_hash,
			t.from_address,
			t.to_address,
			t.block_timestamp,
			t.chain_id,
			t.value,
			t.input,
			t.block_number,
			t.transaction_index,
			t.dummy,
			COALESCE(logs_agg.logs, '[]'::jsonb) as logs
		FROM transactions t
		LEFT JOIN LATERAL (
			SELECT jsonb_agg(
				jsonb_build_object(
					'ingested_at', l.ingested_at,
					'processed_at', l.processed_at,
					'address', l.address,
					'data', l.data,
					'topics', l.topics,
					'topic0', l.topic0,
					'stream_id', l.stream_id,
					'log_index', l.log_index,
					'removed', l.removed
				) ORDER BY l.log_index
			) as logs
			FROM tx_logs l
			WHERE l.transaction_hash = t.transaction_hash 
		) logs_agg ON true
		WHERE MOD(t.i, %[1]v) = %[2]v 
			AND t.dummy = FALSE
			AND (t.block_number, t.transaction_index) > ($1, $2)
		ORDER BY t.block_number, t.transaction_index
		LIMIT %[3]v) normal
		-- TODO: remove with dummy generator
		UNION ALL (
		    SELECT 
			t.transaction_hash,
			t.from_address,
			t.to_address,
			t.block_timestamp,
			t.chain_id,
			t.value,
			t.input,
			t.block_number,
			t.transaction_index,
			t.dummy,
			COALESCE(logs_agg.logs, '[]'::jsonb) as logs
		FROM transactions t
		LEFT JOIN LATERAL (
			SELECT jsonb_agg(
				jsonb_build_object(
					'ingested_at', l.ingested_at,
					'processed_at', l.processed_at,
					'address', l.address,
					'data', l.data,
					'topics', l.topics,
					'topic0', l.topic0,
					'stream_id', l.stream_id,
					'log_index', l.log_index,
					'removed', l.removed
				) ORDER BY l.log_index
			) as logs
			FROM tx_logs l
			WHERE l.transaction_hash = t.transaction_hash 
		) logs_agg ON true
		WHERE MOD(t.i, %[1]v) = %[2]v 
			AND t.dummy = TRUE
			AND (t.block_number, t.transaction_index) > ($3, $4)
		ORDER BY t.block_number, t.transaction_index
		LIMIT %[3]v)
		
		;`, t.cfg.Workers, workerIdx, t.cfg.BatchSize)
	args := []any{start.BlockNumber, start.TransactionIndex, dummyStart.BlockNumber, dummyStart.TransactionIndex}
	events, err := storage.Select[txEvent](ctx, t.ingestedDataDB, sql, args...)

	return events, errors.Wrapf(err, "failed to fetch events for worker:%v", workerIdx)
}

func (s *savePointData) Key() string {
	if s.IsDummy {
		return fmt.Sprintf("token_analytics:save_point:dummy:worker:%v", s.WorkerIdx)
	}
	return fmt.Sprintf("token_analytics:save_point:worker:%v", s.WorkerIdx)
}

func (t *tokenAnalytics) getSavePoint(ctx context.Context, workerIdx uint) (*SavePoint, error) {
	key := fmt.Sprintf("token_analytics:save_point:worker:%v", workerIdx)
	results, err := storagev3.Get[savePointData](ctx, t.processedDataDB, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get save point for worker %v: %w", workerIdx, err)
	}

	if len(results) == 0 || results[0] == nil || (results[0].BlockNumber == 0 && results[0].TransactionIndex == 0) {
		return &SavePoint{
			BlockNumber:      0,
			TransactionIndex: 0,
		}, nil
	}

	return &SavePoint{
		BlockNumber:      results[0].BlockNumber,
		TransactionIndex: results[0].TransactionIndex,
		BlockTime:        results[0].BlockTime,
	}, nil
}

func (t *tokenAnalytics) getDummySavePoint(ctx context.Context, workerIdx uint) (*SavePoint, error) {
	key := fmt.Sprintf("token_analytics:save_point:dummy:worker:%v", workerIdx)
	results, err := storagev3.Get[savePointData](ctx, t.processedDataDB, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get dummy save point for worker %v: %w", workerIdx, err)
	}

	if len(results) == 0 || results[0] == nil {
		return &SavePoint{
			BlockNumber:      0,
			TransactionIndex: 0,
		}, nil
	}

	return &SavePoint{
		BlockNumber:      results[0].BlockNumber,
		TransactionIndex: results[0].TransactionIndex,
		BlockTime:        results[0].BlockTime,
	}, nil
}

func (t *tokenAnalytics) setDummySavePoint(ctx context.Context, workerIdx uint, newSavePoint *SavePoint) error {
	sp := &savePointData{
		WorkerIdx:        workerIdx,
		BlockNumber:      newSavePoint.BlockNumber,
		TransactionIndex: newSavePoint.TransactionIndex,
		UpdatedAt:        time.Now().UnixNano(),
		BlockTime:        newSavePoint.BlockTime,
		IsDummy:          true, // Mark as dummy savepoint
	}
	return storagev3.Set(ctx, t.processedDataDB, sp)
}

func (t *tokenAnalytics) setSavePoint(ctx context.Context, workerIdx uint, newSavePoint *SavePoint) error {
	currentSavePoint, err := t.getSavePoint(ctx, workerIdx)
	if err != nil {
		return fmt.Errorf("failed to get current save point for validation: %w", err)
	}

	if !isValidSavePointProgression(currentSavePoint, newSavePoint) {
		return fmt.Errorf(
			"save point regression detected for worker %d: current(block=%d,tx=%d) -> new(block=%d,tx=%d)",
			workerIdx,
			currentSavePoint.BlockNumber, currentSavePoint.TransactionIndex,
			newSavePoint.BlockNumber, newSavePoint.TransactionIndex,
		)
	}

	sp := &savePointData{
		WorkerIdx:        workerIdx,
		BlockNumber:      newSavePoint.BlockNumber,
		TransactionIndex: newSavePoint.TransactionIndex,
		BlockTime:        newSavePoint.BlockTime,
		UpdatedAt:        time.Now().UnixNano(),
	}

	if err := storagev3.Set(ctx, t.processedDataDB, sp); err != nil {
		return fmt.Errorf("failed to set save point for worker %v: %w", workerIdx, err)
	}

	return nil
}

func isValidSavePointProgression(current, new *SavePoint) bool {
	if new.BlockNumber < current.BlockNumber {
		return false
	}
	if new.BlockNumber == current.BlockNumber && new.TransactionIndex < current.TransactionIndex {
		return false
	}
	return true
}

func (l *txEventLogs) Scan(src any) error {
	valBytes, isBytes := src.([]byte)
	if !isBytes {
		val, isStr := src.(string)
		if !isStr {
			return fmt.Errorf("unexpected type for src:%#v(%T)", src, src)
		}
		if val == "" || val == "[]" {
			*l = make(txEventLogs, 0)

			return nil
		}
		valBytes = []byte(val)
	}
	if len(valBytes) > 2 {
		if err := json.Unmarshal(valBytes, l); err != nil {
			return fmt.Errorf("failed to json.Unmarshal(%v,*txEventLogs): %w", string(valBytes), err)
		}
		return nil
	}
	*l = make(txEventLogs, 0)

	return nil
}

func (j *JSON) getString(key string) (string, bool) {
	val, ok := (*j)[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)

	return str, ok
}

func (j *JSON) getStringSlice(key string) ([]string, bool) {
	val, ok := (*j)[key]
	if !ok {
		return nil, false
	}
	slice, ok := val.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if str, ok := item.(string); ok {
			result = append(result, str)
		}
	}

	return result, true
}

func initializeWorkersConfig(ctx context.Context, db *storage.DB, workers uint) error {
	_, err := storage.Exec(ctx, db, `
		INSERT INTO global_settings (key, value)
		VALUES ('workers', $1)
		ON CONFLICT (key) 
		DO UPDATE SET value = EXCLUDED.value
	`, strconv.FormatUint(uint64(workers), 10))
	if err != nil {
		if storage.IsErr(err, storage.ErrReadOnly) {
			err = nil
		}
		if err != nil {
			return fmt.Errorf("failed to set workers in global_settings table: %w", err)
		}
	}
	_, err = storage.Exec(ctx, db, `SELECT create_transactions_mod_index()`)
	if err != nil {
		if storage.IsErr(err, storage.ErrReadOnly) {
			err = nil
		}
		if err != nil {
			return fmt.Errorf("failed to create transactions mod index: %w", err)
		}
	}

	return nil
}

func (dummyUserRepository) UpsertUser(context.Context, string, string, string, string, string, string, *bool, []string) error {
	return nil
}

func (dummyUserRepository) SetVerified(context.Context, string) error {
	return nil
}

func (dummyUserRepository) GetUser(context.Context, string) (*UserRecord, error) {
	return nil, nil
}

func (dummyUserRepository) HealthCheck(context.Context) error {
	return nil
}

func (dummyUserRepository) Close() error {
	return nil
}

func (dummyUserRepository) UpdateBNBPrice(ctx context.Context, price float64) error {
	return nil
}

func (dummyUserRepository) GetTokenUpdates(ctx context.Context, contractAddress []string) (map[string]coins.TokenAnalyticsToken, error) {
	return nil, nil
}

func (dummyUserRepository) UpdateUserProfileAndToken(ctx context.Context, masterPubkey, username, displayName, avatar string) error {
	return nil
}

func randInt(n int) int {
	return rand.Intn(n)
}
