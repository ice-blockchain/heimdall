// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/go-multierror"
	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/quicknode"
	appconfig "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/log"
	"github.com/pkg/errors"
)

func New(ctx context.Context) TokenAnalytics {
	var cfg config
	appconfig.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.Workers == 0 {
		cfg.Workers = 1
	}
	db := storage.MustConnect(ctx, fmt.Sprintf(sourceDDL, cfg.Workers), applicationYamlKey)
	targetDB := storagev3.MustConnect(ctx, applicationYamlKey)
	qn := quicknode.NewClient(ctx, applicationYamlKey)
	t := &tokenAnalytics{
		ingestedDataDB:  db,
		processedDataDB: targetDB,
		wg:              new(sync.WaitGroup),
		cfg:             &cfg,
		quickNode:       qn,
		shutdown: func() error {
			return multierror.Append(
				errors.Wrapf(db.Close(), "failed to close source db"),
				errors.Wrapf(targetDB.Close(), "failed to close target db"),
			)
		},
	}

	return t
}

func (t *tokenAnalytics) Close() error {
	t.wg.Wait()
	return t.shutdown()
}

func (t *tokenAnalytics) MustStart(ctx context.Context) {
	for workerIdx := range t.cfg.Workers {
		t.wg.Go(func() {
			t.runEventsProcessor(ctx, workerIdx)
		})
	}
}

func (t *tokenAnalytics) runEventsProcessor(ctx context.Context, workerIdx uint) {
	var (
		now, lastIterationStartedAt = time.Now(), time.Now()
		errs                        = make([]error, 0)
		eventsToProcess             = make([]*txEvent, 0, t.cfg.BatchSize)
		err                         error
	)
	startPoint, err := t.getSavePoint(ctx, workerIdx)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to get save point"))
	}
	resetVars := func(success bool) {
		if !success {
			time.Sleep(1 * time.Second)
		}
		now = time.Now()
		errs = errs[:0]
		eventsToProcess = eventsToProcess[:0]
		lastIterationStartedAt = now
	}
	for ctx.Err() == nil {
		iterationCtx, iterationCancel := context.WithTimeout(ctx, 30*time.Second)
		eventsToProcess, err = t.fetchUnprocessedEvents(iterationCtx, workerIdx, startPoint)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to fetch new tx events %v", workerIdx))
			iterationCancel()
			resetVars(false)
		}
		if len(eventsToProcess) == 0 {
			time.Sleep(1 * time.Second)
			iterationCancel()
			continue
		}
		for _, event := range eventsToProcess {
			if err = t.processEvent(iterationCtx, event); err != nil {
				log.Error(errors.Wrapf(err, "failed to process tx event %+v", event))
				resetVars(false)
				iterationCancel()
				continue
			}
			if event.BlockNumber > startPoint.BlockNumber {
				startPoint.BlockNumber = event.BlockNumber
			}
			if event.TransactionIndex > startPoint.TransactionIndex {
				startPoint.TransactionIndex = event.TransactionIndex
			}
			if event.LogIndex > startPoint.LogIndex {
				startPoint.LogIndex = event.LogIndex
			}
		}
		if err = t.setSavePoint(iterationCtx, workerIdx, startPoint); err != nil {
			resetVars(false)
			iterationCancel()
			continue
		}
		iterationCancel()
		resetVars(true)
		log.Info("Iteration took %v", time.Since(lastIterationStartedAt))
	}
}

func (t *tokenAnalytics) processEvent(ctx context.Context, event *txEvent) error {
	err, parsedEv := bondingcurve.ProcessEvent(event.Topic0, event.Data)
	if err != nil {
		return err
	}
	if tokenCreatedEvent, ok := parsedEv.(*bondingcurve.LogTokenCreated); ok {
		tokenCreatedEvent.Address = common.HexToAddress(event.Topics[1]) // Indexed
		log.Info(fmt.Sprintf("Token created:%v %+v ", event.Address, tokenCreatedEvent))
		if strings.EqualFold(event.Address, t.cfg.BondingCurveContract) {
			return errors.Wrapf(t.createStreamForContractAddress(ctx, tokenCreatedEvent.Address.String()), "failed to create stream  fo monitor contract %v", tokenCreatedEvent.Address.String())
		}
	}

	return nil
}

func (t *tokenAnalytics) createStreamForContractAddress(ctx context.Context, contractAddress string) error {
	_, err := storage.Exec(ctx, t.ingestedDataDB, `INSERT INTO streams(contract_address) VALUES ($1);`, contractAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return nil
		}
		return errors.Wrapf(err, "failed to check stream duplicate")
	}
	stream, err := t.quickNode.CreateStream(ctx, contractAddress, contractAddress)
	if err != nil {
		_, rollbackErr := storage.Exec(ctx, t.ingestedDataDB, `DELETE FROM streams WHERE contract_address = $1;`, contractAddress)
		return errors.Wrapf(multierror.Append(err, rollbackErr).ErrorOrNil(), "failed to create stream on qn for %v", contractAddress)
	}
	_, err = storage.Exec(ctx, t.ingestedDataDB, `
			UPDATE streams SET
			    stream_id = $2,
			    created_at = $3,
			    name = $4
			WHERE contract_address = $1;`, contractAddress, stream.ID, stream.CreatedAt, stream.Name)
	return errors.Wrapf(err, "failed to update stream data for %v", contractAddress)
}

func (t *tokenAnalytics) fetchUnprocessedEvents(ctx context.Context, workerIdx uint, start *SavePoint) ([]*txEvent, error) {
	sql := fmt.Sprintf(`SELECT tx_logs.*, 
       							transactions.transaction_index as transaction_index,
       							transactions.from_address
				FROM tx_logs
                		JOIN transactions ON tx_logs.transaction_hash = transactions.transaction_hash
						WHERE MOD(i, %[1]v) = %[2]v
							AND tx_logs.block_number >= $1 
						    AND transactions.transaction_index >= $2 
						    AND tx_logs.log_index > $3
						ORDER BY MOD(i, %[1]v), 
						    	 tx_logs.block_number,
						    	 transactions.transaction_index,
						    	 tx_logs.log_index
						LIMIT %[3]v;`, t.cfg.Workers, workerIdx, t.cfg.BatchSize)
	events, err := storage.Select[txEvent](ctx, t.ingestedDataDB, sql, start.BlockNumber, start.TransactionIndex, start.LogIndex)

	return events, errors.Wrapf(err, "failed to fetch events for worker:%v", workerIdx)
}

func (t *tokenAnalytics) getSavePoint(ctx context.Context, workerIdx uint) (*SavePoint, error) {
	return &SavePoint{
		TransactionIndex: 0,
		BlockNumber:      9553981,
		LogIndex:         0,
	}, nil
}

func (t *tokenAnalytics) setSavePoint(ctx context.Context, workerIdx uint, savePoint *SavePoint) error {
	return nil
}
