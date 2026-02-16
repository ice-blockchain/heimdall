// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestHourlyRankingWorker_ComputeAndStore(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	helperInsertTestUser(t, ctx, db, "hrw_creator1", "hrw_one", "HRW One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "hrw_creator2", "hrw_two", "HRW Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "hrw_creator3", "hrw_three", "HRW Three", "", true, PlatformGroupIonConnect)

	token1Ext := "0:hrw_creator1:"
	token2Ext := "0:hrw_creator2:"
	token3Ext := "0:hrw_creator3:"

	helperInsertTestToken(t, ctx, db, "0xHRW1111111111111111111111111111111111111", token1Ext, "HRW1", "profile", "hrw_creator1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xHRW2222222222222222222222222222222222222", token2Ext, "HRW2", "profile", "hrw_creator2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xHRW3333333333333333333333333333333333333", token3Ext, "HRW3", "profile", "hrw_creator3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	targetHour := time.Date(2021, 6, 15, 10, 0, 0, 0, time.UTC)
	swapTime := targetHour.Add(30 * time.Minute) // Middle of the target hour.

	// Token1: buy 100 tokens at price 0.50 USD -> volume = 100 * 0.50 = 50 USD
	helperCreateSwapAtTime(t, ctx, db, "0xHRW1111111111111111111111111111111111111", token1Ext, "0xBUYER1", false,
		"100000000000000000000", "1000000000000000000000", 0.50, swapTime)

	// Token2: buy 200 tokens at price 1.00 USD -> volume = 200 * 1.00 = 200 USD
	helperCreateSwapAtTime(t, ctx, db, "0xHRW2222222222222222222222222222222222222", token2Ext, "0xBUYER2", false,
		"200000000000000000000", "2000000000000000000000", 1.00, swapTime)

	// Token3: sell 50 tokens at price 2.00 USD -> volume = 50 * 2.00 = 100 USD
	helperCreateSwapAtTime(t, ctx, db, "0xHRW3333333333333333333333333333333333333", token3Ext, "0xSELLER3", true,
		"50000000000000000000", "500000000000000000000", 2.00, swapTime)

	require.NoError(t, ta.computeAndStoreHourlyRanking(ctx, targetHour))

	processed, err := ta.isHourProcessed(ctx, targetHour)
	require.NoError(t, err)
	require.True(t, processed, "hour should be marked as processed")

	time.Sleep(500 * time.Millisecond)

	tokens, err := ta.GetCommunityTokensByRewardsDistribution(ctx, targetHour, 10, 0)
	require.NoError(t, err)
	require.Len(t, tokens, 3, "should have 3 tokens in hourly ranking")

	// Ranking order based on amount_wei * price_usd:
	// Token2: output_amount(2e21) * 1.00 = 2e21
	// Token1: output_amount(1e21) * 0.50 = 5e20
	// Token3: input_amount(5e19) * 2.00 = 1e20
	require.Equal(t, token2Ext, tokens[0].Addresses.IonConnect)
	require.Equal(t, token1Ext, tokens[1].Addresses.IonConnect)
	require.Equal(t, token3Ext, tokens[2].Addresses.IonConnect)
}

func TestHourlyRankingWorker_EmptyHour(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, ta.computeAndStoreHourlyRanking(ctx, targetHour))

	processed, err := ta.isHourProcessed(ctx, targetHour)
	require.NoError(t, err)
	require.True(t, processed, "empty hour should be marked as processed")
	tokens, err := ta.GetCommunityTokensByRewardsDistribution(ctx, targetHour, 10, 0)
	require.NoError(t, err)
	require.Empty(t, tokens, "empty hour should return 0 tokens")
}

func TestHourlyRankingWorker_BackfillIdempotent(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	err := ta.computeAndStoreHourlyRanking(ctx, targetHour)
	require.NoError(t, err)

	processed, err := ta.isHourProcessed(ctx, targetHour)
	require.NoError(t, err)
	require.True(t, processed)
}

func helperCreateSwapAtTime(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, userAddress string, direction bool,
	inputAmount, outputAmount string, priceUSD float64, createdAt time.Time) {
	t.Helper()

	txHash := fmt.Sprintf("0x%s%d", contractAddress[2:10], createdAt.UnixNano())
	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_blockchain_address, direction, input_amount, output_amount, fee, price_usd
		)
		VALUES ($1, $2, $3, $4, LOWER($5), $6, $7, $8, 0, $9)
		ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		createdAt,
		txHash,
		contractAddress,
		externalAddress,
		userAddress,
		direction,
		inputAmount,
		outputAmount,
		priceUSD,
	)

	require.NoError(t, err, "failed to insert token swap at time")
}
