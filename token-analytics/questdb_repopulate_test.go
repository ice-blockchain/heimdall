// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestRepopulateQuestDBTrades(t *testing.T) {
	t.Run("repopulates_swaps_into_questdb", func(t *testing.T) {
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()
		ta := helperNewForTestWithConnString(t, db, connString)
		defer ta.Close()

		creatorPubkey := "repop_questdb_creator"
		contractAddr := "0xrepop_questdb_contract_0000000000000000001"
		extAddr := "0:repop_questdb_ext:"
		userAddr := "0xrepop_questdb_user_00000000000000000000001"
		pairID := "0x000000000000000000000000000000000000dead"
		baseToken := strings.ToLower(ta.cfg.IONTokenAddress)

		helperInsertTestUser(t, ctx, db, creatorPubkey, "repop_q_user", "Repop Q User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, extAddr, "REPOPQ", TokenTypePost, creatorPubkey,
			"1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, extAddr, pairID, baseToken)

		swapTime := stdlibtime.Now().Add(-1 * stdlibtime.Hour).Truncate(stdlibtime.Second)
		helperInsertTokenSwapWithCurvePrice(t, ctx, db,
			contractAddr, extAddr, userAddr, "0xrepop_questdb_tx_001",
			false, "1000000000000000000", "10000000000000000000",
			0.10, 0.10, swapTime)

		err := ta.processedDataDB.Del(ctx, redisKeyLastQuestDBSync).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)

		type tradeRow struct {
			ExternalAddress string `db:"external_address"`
			TradeType       string `db:"trade_type"`
			TraderAddress   string `db:"trader_address"`
			TransactionHash string `db:"transaction_hash"`
		}
		var row *tradeRow
		require.Eventually(t, func() bool {
			row, err = questdb.Get[tradeRow](ctx, ta.questDB,
				`SELECT external_address, trade_type, trader_address, transaction_hash FROM trades WHERE transaction_hash = $1`,
				"0xrepop_questdb_tx_001")
			return err == nil && row != nil
		}, 30*stdlibtime.Second, 200*stdlibtime.Millisecond, "QuestDB should contain repopulated trade")

		require.Equal(t, extAddr, row.ExternalAddress)
		require.Equal(t, "buy", row.TradeType)
		require.Equal(t, strings.ToLower(userAddr), row.TraderAddress)

		lastSync, err := ta.processedDataDB.Get(ctx, redisKeyLastQuestDBSync).Result()
		require.NoError(t, err)
		require.NotEmpty(t, lastSync, "last QuestDB sync timestamp should be set")
	})

	t.Run("returns_nil_when_no_swaps", func(t *testing.T) {
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()
		ta := helperNewForTestWithConnString(t, db, connString)
		defer ta.Close()

		err := ta.processedDataDB.Del(ctx, redisKeyLastQuestDBSync).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)
	})

	t.Run("deduplicates_already_registered_trades", func(t *testing.T) {
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()
		ta := helperNewForTestWithConnString(t, db, connString)
		defer ta.Close()

		creatorPubkey := "repop_dedup_creator"
		contractAddr := "0xrepop_dedup_contract_000000000000000000001"
		extAddr := "0:repop_dedup_ext:"
		userAddr := "0xrepop_dedup_user_0000000000000000000000001"
		pairID := "0x000000000000000000000000000000000000dead"
		baseToken := strings.ToLower(ta.cfg.IONTokenAddress)

		helperInsertTestUser(t, ctx, db, creatorPubkey, "repop_d_user", "Repop D User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, extAddr, "REPOPD", TokenTypePost, creatorPubkey,
			"1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, extAddr, pairID, baseToken)

		swapTime := stdlibtime.Now().Add(-30 * stdlibtime.Minute).Truncate(stdlibtime.Second)
		helperInsertTokenSwapWithCurvePrice(t, ctx, db,
			contractAddr, extAddr, userAddr, "0xrepop_dedup_tx_001",
			false, "1000000000000000000", "10000000000000000000",
			0.10, 0.10, swapTime)

		err := ta.processedDataDB.Del(ctx, redisKeyLastQuestDBSync).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)

		type tradeRow struct {
			TransactionHash string `db:"transaction_hash"`
		}
		var row *tradeRow
		require.Eventually(t, func() bool {
			row, err = questdb.Get[tradeRow](ctx, ta.questDB,
				`SELECT transaction_hash FROM trades WHERE transaction_hash = $1`,
				"0xrepop_dedup_tx_001")
			return err == nil && row != nil
		}, 30*stdlibtime.Second, 200*stdlibtime.Millisecond, "QuestDB should contain the trade after first run")

		// Reset sync marker to force second pass over the same swaps.
		err = ta.processedDataDB.Del(ctx, redisKeyLastQuestDBSync).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)

		type countRow struct {
			Cnt int64 `db:"cnt"`
		}
		var cntRow *countRow
		require.Eventually(t, func() bool {
			cntRow, err = questdb.Get[countRow](ctx, ta.questDB,
				`SELECT count(*) as cnt FROM trades WHERE transaction_hash = $1`,
				"0xrepop_dedup_tx_001")
			return err == nil && cntRow != nil
		}, 30*stdlibtime.Second, 200*stdlibtime.Millisecond, "QuestDB count query should succeed")

		require.Equal(t, int64(1), cntRow.Cnt, "QuestDB DEDUP should prevent duplicate rows")
	})
	t.Run("respects_last_sync_timestamp", func(t *testing.T) {
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()
		ta := helperNewForTestWithConnString(t, db, connString)
		defer ta.Close()

		creatorPubkey := "repop_sync_creator"
		contractAddr := "0xrepop_sync_contract_00000000000000000001"
		extAddr := "0:repop_sync_ext:"
		userAddr := "0xrepop_sync_user_0000000000000000000000001"
		pairID := "0x000000000000000000000000000000000000dead"
		baseToken := strings.ToLower(ta.cfg.IONTokenAddress)

		helperInsertTestUser(t, ctx, db, creatorPubkey, "repop_s_user", "Repop S User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, extAddr, "REPOPS", TokenTypePost, creatorPubkey,
			"1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, extAddr, pairID, baseToken)

		oldSwapTime := stdlibtime.Now().Add(-48 * stdlibtime.Hour).Truncate(stdlibtime.Second)
		helperInsertTokenSwapWithCurvePrice(t, ctx, db,
			contractAddr, extAddr, userAddr, "0xrepop_sync_old_tx",
			false, "1000000000000000000", "10000000000000000000",
			0.10, 0.10, oldSwapTime)

		newSwapTime := stdlibtime.Now().Add(-1 * stdlibtime.Hour).Truncate(stdlibtime.Second)
		helperInsertTokenSwapWithCurvePrice(t, ctx, db,
			contractAddr, extAddr, userAddr, "0xrepop_sync_new_tx",
			false, "2000000000000000000", "20000000000000000000",
			0.20, 0.20, newSwapTime)

		// Set last sync to 2 hours ago — should skip the old swap, pick up the new one.
		syncTime := stdlibtime.Now().Add(-2 * stdlibtime.Hour)
		err := ta.processedDataDB.Set(ctx, redisKeyLastQuestDBSync, syncTime.Format(stdlibtime.RFC3339), 0).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)

		type tradeRow struct {
			TransactionHash string `db:"transaction_hash"`
		}
		var row *tradeRow
		require.Eventually(t, func() bool {
			row, err = questdb.Get[tradeRow](ctx, ta.questDB,
				`SELECT transaction_hash FROM trades WHERE transaction_hash = $1`,
				"0xrepop_sync_new_tx")
			return err == nil && row != nil
		}, 30*stdlibtime.Second, 200*stdlibtime.Millisecond, "QuestDB should contain the new trade")

		_, err = questdb.Get[tradeRow](ctx, ta.questDB,
			`SELECT transaction_hash FROM trades WHERE transaction_hash = $1`,
			"0xrepop_sync_old_tx")
		require.Error(t, err, "QuestDB should NOT contain the old trade (before last sync)")
	})

	t.Run("handles_multiple_swaps", func(t *testing.T) {
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()
		ta := helperNewForTestWithConnString(t, db, connString)
		defer ta.Close()

		creatorPubkey := "repop_multi_creator"
		contractAddr := "0xrepop_multi_contract_000000000000000000001"
		extAddr := "0:repop_multi_ext:"
		userAddr := "0xrepop_multi_user_00000000000000000000000001"
		pairID := "0x000000000000000000000000000000000000dead"
		baseToken := strings.ToLower(ta.cfg.IONTokenAddress)

		helperInsertTestUser(t, ctx, db, creatorPubkey, "repop_m_user", "Repop M User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, extAddr, "REPOPM", TokenTypePost, creatorPubkey,
			"1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, extAddr, pairID, baseToken)

		baseTime := stdlibtime.Now().Add(-3 * stdlibtime.Hour).Truncate(stdlibtime.Second)
		for i := 0; i < 5; i++ {
			txHash := fmt.Sprintf("0xrepop_multi_tx_%03d", i)
			swapTime := baseTime.Add(stdlibtime.Duration(i) * stdlibtime.Minute)
			helperInsertTokenSwapWithCurvePrice(t, ctx, db,
				contractAddr, extAddr, userAddr, txHash,
				i%2 == 0, "1000000000000000000", "10000000000000000000",
				0.10, 0.10, swapTime)
		}

		err := ta.processedDataDB.Del(ctx, redisKeyLastQuestDBSync).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)

		type countRow struct {
			Cnt int64 `db:"cnt"`
		}
		var cntRow *countRow
		require.Eventually(t, func() bool {
			cntRow, err = questdb.Get[countRow](ctx, ta.questDB,
				`SELECT count(*) as cnt FROM trades WHERE external_address = $1`,
				extAddr)
			return err == nil && cntRow != nil && cntRow.Cnt == 5
		}, 30*stdlibtime.Second, 200*stdlibtime.Millisecond,
			"QuestDB should contain all 5 trades")

		require.Equal(t, int64(5), cntRow.Cnt)
	})

	t.Run("skips_swaps_with_zero_curve_price", func(t *testing.T) {
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()
		ta := helperNewForTestWithConnString(t, db, connString)
		defer ta.Close()

		creatorPubkey := "repop_zero_creator"
		contractAddr := "0xrepop_zero_contract_00000000000000000001"
		extAddr := "0:repop_zero_ext:"
		userAddr := "0xrepop_zero_user_0000000000000000000000001"
		pairID := "0x000000000000000000000000000000000000dead"
		baseToken := strings.ToLower(ta.cfg.IONTokenAddress)

		helperInsertTestUser(t, ctx, db, creatorPubkey, "repop_z_user", "Repop Z User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, extAddr, "REPOPZ", TokenTypePost, creatorPubkey,
			"1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, extAddr, pairID, baseToken)

		swapTime := stdlibtime.Now().Add(-1 * stdlibtime.Hour).Truncate(stdlibtime.Second)
		helperInsertTokenSwapWithCurvePrice(t, ctx, db,
			contractAddr, extAddr, userAddr, "0xrepop_zero_tx_001",
			false, "1000000000000000000", "10000000000000000000",
			0.10, 0.0, swapTime)

		err := ta.processedDataDB.Del(ctx, redisKeyLastQuestDBSync).Err()
		require.NoError(t, err)

		err = ta.RepopulateQuestDBTrades(ctx)
		require.NoError(t, err)

		type tradeRow struct {
			TransactionHash string `db:"transaction_hash"`
		}

		require.Never(t, func() bool {
			_, qErr := questdb.Get[tradeRow](ctx, ta.questDB,
				`SELECT transaction_hash FROM trades WHERE transaction_hash = $1`,
				"0xrepop_zero_tx_001")
			return qErr == nil
		}, 3*stdlibtime.Second, 200*stdlibtime.Millisecond, "swaps with curve_price_usd=0 should be excluded from repopulation")
	})
}

func helperInsertTokenSwapWithCurvePrice(
	t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, userAddress, txHash string,
	direction bool, inputAmount, outputAmount string,
	priceUSD, curvePriceUSD float64, createdAt stdlibtime.Time,
) {
	t.Helper()

	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_blockchain_address, direction, input_amount, output_amount, price_usd, fee, curve_price_usd
		)
		VALUES ($1, $2, $3, $4, LOWER($5), $6, $7, $8, $9, 0, $10)
		ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		createdAt, txHash, contractAddress, externalAddress, userAddress,
		direction, inputAmount, outputAmount, priceUSD, curvePriceUSD,
	)
	require.NoError(t, err, "failed to insert token swap with curve price")
}
