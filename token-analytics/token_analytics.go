// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"
	"sync"
	"time"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/rcrowley/go-metrics"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/quicknode"
	appconfig "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/log"
)

func New(ctx context.Context) TokenAnalytics {
	var cfg config
	appconfig.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.Workers == 0 {
		cfg.Workers = 1
	}
	appconfig.MustLoadFromKey("bondingCurveContract", &cfg.BondingCurveContract)

	db := storage.MustConnect(ctx, fmt.Sprintf(sourceDDL, cfg.Workers), applicationYamlKey)
	targetDB := storagev3.MustConnect(ctx, applicationYamlKey)
	qn := quicknode.NewClient(ctx, applicationYamlKey)

	registry := metrics.NewRegistry()
	for workerIdx := range cfg.Workers {
		workerPrefix := fmt.Sprintf("worker_%d_", workerIdx)
		log.Panic(errors.Wrapf(registry.Register(workerPrefix+"iteration",
			metrics.NewCustomTimer(metrics.NewHistogram(metrics.NewExpDecaySample(10_000, 0.015)), metrics.NewMeter())),
			"failed to register worker %d iteration timer", workerIdx))
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

	t := &tokenAnalytics{
		ingestedDataDB:  db,
		processedDataDB: targetDB,
		wg:              new(sync.WaitGroup),
		cfg:             &cfg,
		quickNode:       qn,
		metrics:         registry,
		shutdown: func() error {
			return errors.Join(
				errors.Wrapf(db.Close(), "failed to close source db"),
				errors.Wrapf(targetDB.Close(), "failed to close target db"),
			)
		},
	}

	go metrics.LogScaled(registry, 10*stdlibtime.Second, 1*stdlibtime.Millisecond, t) // TODO: 10 secs for test, change to 1-15 mminutes.
	go t.startIONPriceSyncer(ctx)
	return t
}

func (t *tokenAnalytics) Close() error {
	t.wg.Wait()
	log.Info("all workers stopped")

	return t.shutdown()
}

func (t *tokenAnalytics) Healthcheck(ctx context.Context) error {
	if err := t.ingestedDataDB.Ping(ctx); err != nil {
		return errors.Wrap(err, "database connection failed")
	}
	if err := t.processedDataDB.Ping(ctx).Err(); err != nil {
		return errors.Wrap(err, "redis connection failed")
	}
	if err := t.quickNode.HealthCheck(ctx); err != nil {
		return errors.Wrap(err, "quicknode api unavailable")
	}

	return nil
}

func (t *tokenAnalytics) UpsertUser(ctx context.Context, id, masterPubkey, username, displayName, avatar string, verified bool, ionConnectRelays []string) error {
	lookup := strings.ToLower(strings.TrimSpace(username + " " + displayName))

	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, username, 
			display_name, avatar, lookup, ion_connect_relays, verified
		) VALUES (
			NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			updated_at = NOW(),
			id = EXCLUDED.id,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			avatar = EXCLUDED.avatar,
			lookup = EXCLUDED.lookup,
			ion_connect_relays = EXCLUDED.ion_connect_relays,
			verified = EXCLUDED.verified
	`, id, masterPubkey, username, displayName, avatar, lookup, ionConnectRelays, verified)

	return errors.Wrapf(err, "failed to upsert user %v", masterPubkey)
}

func (t *tokenAnalytics) SetVerified(ctx context.Context, masterPubkey string) error {
	_, err := storage.Exec(ctx, t.ingestedDataDB, `
		UPDATE users 
		SET verified = true, updated_at = NOW()
		WHERE master_pubkey = $1
	`, masterPubkey)

	return errors.Wrapf(err, "failed to set verified for user %v", masterPubkey)
}

func (t *tokenAnalytics) MustStart(ctx context.Context) {
	for workerIdx := range t.cfg.Workers {
		t.wg.Go(func() {
			t.runEventsProcessor(ctx, workerIdx)
		})
	}
}

func (t *tokenAnalytics) runEventsProcessor(ctx context.Context, workerIdx uint) {
	workerPrefix := fmt.Sprintf("worker_%d_", workerIdx)
	iterationTimer := t.metrics.Get(workerPrefix + "iteration").(metrics.Timer)
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
		log.Panic(errors.Wrapf(err, "failed to get save point for worker %d", workerIdx))
	}
	log.Info(fmt.Sprintf("Worker %d started from block %d", workerIdx, startPoint.BlockNumber))

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
		eventsToProcess, err = t.fetchUnprocessedEvents(iterationCtx, workerIdx, startPoint)
		if err != nil {
			log.Error(errors.Wrapf(err, "[worker %d] failed to fetch new tx events", workerIdx))
			iterationCancel()
			resetVars(false)

			continue
		}
		if len(eventsToProcess) == 0 {
			time.Sleep(1 * time.Second)
			iterationCancel()

			continue
		}

		for _, tx := range eventsToProcess {
			for _, logEvent := range tx.Logs {
				if err = t.processLog(iterationCtx, tx, &logEvent); err != nil {
					log.Error(errors.Wrapf(err, "[worker %d] failed to process log %+v in tx %v", workerIdx, logEvent, tx.TransactionHash))
					errorsMeter.Mark(1)

					continue
				}
				eventsProcessed.Mark(1)
			}

			if tx.BlockNumber > startPoint.BlockNumber {
				startPoint.BlockNumber = tx.BlockNumber
				startPoint.TransactionIndex = tx.TransactionIndex
				blockGauge.Update(int64(tx.BlockNumber))
			} else if tx.BlockNumber == startPoint.BlockNumber && tx.TransactionIndex > startPoint.TransactionIndex {
				startPoint.TransactionIndex = tx.TransactionIndex
			}
			transactionGauge.Update(int64(tx.TransactionIndex))
		}

		if err = t.setSavePoint(iterationCtx, workerIdx, startPoint); err != nil {
			log.Error(errors.Wrapf(err, "[worker %d] failed to save point", workerIdx))
			resetVars(false)
			iterationCancel()

			continue
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

	parsedEv, err := bondingcurve.ProcessEvent(topic0, data, topics)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to process event topic0=%s, address=%s, data=%s", topic0, address, data))
		return err
	}

	switch ev := parsedEv.(type) {
	case *bondingcurve.LogTokenCreated:
		return t.onTokenCreated(ctx, tx, logEvent, ev)
	case *bondingcurve.LogTransfer:
		return t.onTransfer(ctx, tx, logEvent, ev)
	case *bondingcurve.LogOwnershipTransferred:
		return t.onOwnershipTransferred(ctx, tx, logEvent, ev)
	case *bondingcurve.LogTokenSwapped:
		return t.onSwap(ctx, tx, logEvent, ev)
	case *bondingcurve.LogPairRegistered:
		return t.onPairRegistered(ctx, tx, logEvent, ev)
	case *bondingcurve.LogRecipientsSet:
		return t.onRecipientsSet(ctx, tx, logEvent, ev)
	case *bondingcurve.LogMigrated:
		return t.onMigrated(ctx, tx, logEvent, ev)
	case *bondingcurve.LogFeeAccrued:
		return t.onFeeAccrued(ctx, tx, logEvent, ev)
	case *bondingcurve.LogFeeTransfer:
		return t.onFeeTransfer(ctx, tx, logEvent, ev)
	case *bondingcurve.LogLiquidityClaimed:
		return t.onLiquidityClaimed(ctx, tx, logEvent, ev)
	case *bondingcurve.LogSlippageChecked:
		return t.onSlippageChecked(ctx, tx, logEvent, ev)
	case *bondingcurve.LogLiquidityLocked:
		return t.onLiquidityLocked(ctx, tx, logEvent, ev)
	}

	return nil
}

func (t *tokenAnalytics) createStreamForContractAddress(ctx context.Context, contractAddress string) error {
	_, err := storage.Exec(ctx, t.ingestedDataDB, `INSERT INTO streams(contract_address) VALUES ($1);`, contractAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			log.Info("Stream already exists for bonded token: %v", contractAddress)
			return nil
		}
		return errors.Wrapf(err, "failed to check stream duplicate")
	}

	stream, err := t.quickNode.CreateStream(ctx, contractAddress, contractAddress)
	if err != nil {
		_, rollbackErr := storage.Exec(ctx, t.ingestedDataDB, `DELETE FROM streams WHERE contract_address = $1;`, contractAddress)
		return errors.Wrapf(errors.Join(err, rollbackErr), "failed to create quicknode stream for %v", contractAddress)
	}

	_, err = storage.Exec(ctx, t.ingestedDataDB, `
      UPDATE streams SET
          stream_id = $2,
          created_at = $3,
          name = $4
      WHERE contract_address = $1;`, contractAddress, stream.ID, stream.CreatedAt, stream.Name)
	if err != nil {
		return errors.Wrapf(err, "failed to insert stream for %v", contractAddress)
	}

	log.Info("Stream created for bonded token: %v (ID: %v)", contractAddress, stream.ID)
	return nil
}

func (t *tokenAnalytics) Printf(format string, args ...interface{}) {
	stdlog.Printf(format, args...)
}

func (t *tokenAnalytics) fetchUnprocessedEvents(ctx context.Context, workerIdx uint, start *SavePoint) ([]*txEvent, error) {
	sql := fmt.Sprintf(`
		SELECT 
			t.transaction_hash,
			t.from_address,
			t.to_address,
			t.block_timestamp,
			t.chain_id,
			t.value,
			t.block_number,
			t.transaction_index,
			COALESCE(
				jsonb_agg(
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
				) FILTER (WHERE l.log_index IS NOT NULL),
				'[]'::jsonb
			) as logs
		FROM transactions t
		LEFT JOIN tx_logs l ON t.transaction_hash = l.transaction_hash
		WHERE MOD(t.transaction_index, %[1]v) = %[2]v 
			AND (t.block_number, t.transaction_index) > ($1, $2)
		GROUP BY t.transaction_hash, t.from_address, t.to_address, t.block_timestamp, 
				 t.chain_id, t.value, t.block_number, t.transaction_index
		ORDER BY t.block_number, t.transaction_index
		LIMIT %[3]v;`, t.cfg.Workers, workerIdx, t.cfg.BatchSize)

	events, err := storage.Select[txEvent](ctx, t.ingestedDataDB, sql, start.BlockNumber, start.TransactionIndex)

	return events, errors.Wrapf(err, "failed to fetch events for worker:%v", workerIdx)
}

func (s *savePointData) Key() string {
	return fmt.Sprintf("token_analytics:save_point:worker:%v", s.WorkerIdx)
}

func (t *tokenAnalytics) getSavePoint(ctx context.Context, workerIdx uint) (*SavePoint, error) {
	key := fmt.Sprintf("token_analytics:save_point:worker:%v", workerIdx)
	results, err := storagev3.Get[savePointData](ctx, t.processedDataDB, key)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get save point for worker %v", workerIdx)
	}

	if len(results) == 0 || results[0] == nil || (results[0].BlockNumber == 0 && results[0].TransactionIndex == 0) {
		startBlock := t.cfg.StartBlock
		if startBlock > 0 {
			startBlock--
		}
		return &SavePoint{
			BlockNumber:      startBlock,
			TransactionIndex: 0,
		}, nil
	}

	return &SavePoint{
		BlockNumber:      results[0].BlockNumber,
		TransactionIndex: results[0].TransactionIndex,
	}, nil
}

func (t *tokenAnalytics) setSavePoint(ctx context.Context, workerIdx uint, newSavePoint *SavePoint) error {
	currentSavePoint, err := t.getSavePoint(ctx, workerIdx)
	if err != nil {
		return errors.Wrapf(err, "failed to get current save point for validation")
	}

	if !isValidSavePointProgression(currentSavePoint, newSavePoint) {
		return errors.Errorf(
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
		UpdatedAt:        time.Now().UnixNano(),
	}

	if err := storagev3.Set(ctx, t.processedDataDB, sp); err != nil {
		return errors.Wrapf(err, "failed to set save point for worker %v", workerIdx)
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
			return errors.Errorf("unexpected type for src:%#v(%T)", src, src)
		}
		if val == "" || val == "[]" {
			*l = make(txEventLogs, 0)

			return nil
		}
		valBytes = []byte(val)
	}
	if len(valBytes) > 2 {
		return errors.Wrapf(json.UnmarshalContext(context.Background(), valBytes, l), "failed to json.UnmarshalContext(%v,*txEventLogs)", string(valBytes))
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
