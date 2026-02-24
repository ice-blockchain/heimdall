// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

const (
	redisKeyLastQuestDBSync = "token_analytics:last_questdb_sync"
)

func (t *tokenAnalytics) RepopulateQuestDBTrades(ctx context.Context) error {
	log.Info("Starting QuestDB trades repopulation...")
	start := time.Now()

	lastSyncStr, err := t.processedDataDB.Get(ctx, redisKeyLastQuestDBSync).Result()
	var lastSync stdlibtime.Time
	if err != nil || lastSyncStr == "" {
		lastSync = stdlibtime.Now().Add(-7 * 24 * stdlibtime.Hour)
		log.Info(fmt.Sprintf("No last QuestDB sync found, starting from %v", lastSync))
	} else {
		lastSync, err = stdlibtime.Parse(stdlibtime.RFC3339, lastSyncStr)
		if err != nil {
			log.Error(errors.Wrap(err, "failed to parse last sync time, using 7 days ago"))
			lastSync = stdlibtime.Now().Add(-7 * 24 * stdlibtime.Hour)
		}
	}
	type swapToRepopulate struct {
		TransactionHash       string          `db:"transaction_hash"`
		ContractAddress       string          `db:"contract_address"`
		ExternalAddress       string          `db:"external_address"`
		UserBlockchainAddress string          `db:"user_blockchain_address"`
		Direction             bool            `db:"direction"`
		InputAmount           string          `db:"input_amount"`
		OutputAmount          string          `db:"output_amount"`
		CurvePriceUSD         float64         `db:"curve_price_usd"`
		CreatedAt             stdlibtime.Time `db:"created_at"`
		BaseToken             string          `db:"base_token"`
		TotalSupply           string          `db:"total_supply"`
		PairID                string          `db:"pair_id"`
		Burned                string          `db:"burned"`
		Platform              string          `db:"platform"`
		Type                  string          `db:"type"`
	}
	swaps, err := storage.Select[swapToRepopulate](ctx, t.ingestedDataDB, `
		SELECT 
			ts.transaction_hash,
			ts.contract_address,
			ts.external_address,
			ts.user_blockchain_address,
			ts.direction,
			ts.input_amount,
			ts.output_amount,
			ts.curve_price_usd,
			ts.created_at,
			t.base_token,
			t.total_supply,
			t.pair_id,
			t.platform,
			t."type",
			COALESCE(burned.amount, 0)::text as burned
		FROM token_swaps ts
		JOIN tokens t ON t.contract_address = ts.contract_address
		LEFT JOIN fees_transferred burned ON burned.token_external_address = t.external_address 
			AND burned.recipient_bsc_address = '0x0000000000000000000000000000000000696f6e'
		WHERE ts.curve_price_usd > 0
		  AND ts.created_at >= $1
		ORDER BY ts.created_at ASC
		LIMIT 10000
	`, lastSync)

	if err != nil {
		return errors.Wrap(err, "failed to query swaps for QuestDB repopulation")
	}
	if len(swaps) == 0 {
		log.Info("No swaps to repopulate in QuestDB")

		return nil
	}
	log.Info(fmt.Sprintf("Found %d swaps to repopulate in QuestDB", len(swaps)))

	processedCount := 0
	errorCount := 0
	for _, swap := range swaps {
		inputAmount, ok := new(big.Int).SetString(swap.InputAmount, 10)
		if !ok {
			log.Error(errors.Errorf("failed to parse input amount %s for tx %s", swap.InputAmount, swap.TransactionHash))
			errorCount++

			continue
		}
		outputAmount, ok := new(big.Int).SetString(swap.OutputAmount, 10)
		if !ok {
			log.Error(errors.Errorf("failed to parse output amount %s for tx %s", swap.OutputAmount, swap.TransactionHash))
			errorCount++

			continue
		}
		totalSupply, ok := new(big.Int).SetString(swap.TotalSupply, 10)
		if !ok {
			log.Error(errors.Errorf("failed to parse total supply %s for tx %s", swap.TotalSupply, swap.TransactionHash))
			errorCount++

			continue
		}
		burned, ok := new(big.Int).SetString(swap.Burned, 10)
		if !ok {
			log.Error(errors.Errorf("failed to parse burned %s for tx %s", swap.Burned, swap.TransactionHash))
			errorCount++
			continue
		}
		pairIdBytes, err := hex.DecodeString(strings.TrimPrefix(swap.PairID, "0x"))
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to decode pair_id %s for tx %s", swap.PairID, swap.TransactionHash))
			errorCount++

			continue
		}
		mCapUSDF := marketCap(swap.CurvePriceUSD, totalSupply, burned)
		mCapUSD, _ := mCapUSDF.Float64()
		tx := &txEvent{
			BlockTimestamp:  time.New(swap.CreatedAt),
			TransactionHash: swap.TransactionHash,
			BlockNumber:     0,
		}
		if err := t.registerTrade(ctx, tx, swap.Direction, inputAmount, outputAmount,
			swap.ContractAddress, swap.UserBlockchainAddress, swap.ExternalAddress,
			swap.BaseToken, pairIdBytes, totalSupply, burned, swap.CurvePriceUSD, mCapUSD); err != nil {
			log.Error(errors.Wrapf(err, "failed to register trade for tx %s", swap.TransactionHash))
			errorCount++

			continue
		}

		if err = t.updateTokenRankingsInRedis(ctx, mCapUSD, swap.ExternalAddress, swap.Platform, swap.Type); err != nil {
			return errors.Wrapf(err, "failed to update redis ranking for tx %v contract %v %v user %v",
				swap.TransactionHash, swap.ContractAddress, swap.ExternalAddress, swap.UserBlockchainAddress)
		}
		tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, swap.TransactionHash, swap.ContractAddress, swap.UserBlockchainAddress)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v contract %v user %v",
				swap.TransactionHash, swap.ContractAddress, swap.UserBlockchainAddress))
			errorCount++

			continue
		}
		t.subscriptions.NotifySwap(tradeInfo)
		processedCount++
		if processedCount%100 == 0 {
			stdlibtime.Sleep(100 * stdlibtime.Millisecond)

			log.Debug(fmt.Sprintf("Processed %d/%d swaps for QuestDB repopulation", processedCount, len(swaps)))
		}
	}
	now := stdlibtime.Now()
	if err := t.processedDataDB.Set(ctx, redisKeyLastQuestDBSync, now.Format(stdlibtime.RFC3339), 0).Err(); err != nil {
		log.Error(errors.Wrap(err, "failed to update last QuestDB sync time"))
	}
	elapsed := stdlibtime.Since(*start.Time)
	log.Info(fmt.Sprintf("QuestDB trades repopulation completed in %v: %d swaps processed, %d errors", elapsed, processedCount, errorCount))

	return nil
}
