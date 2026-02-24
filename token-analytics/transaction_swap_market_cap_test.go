// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	bondingcurvefixture "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
)

func TestCalculateTokenMarketDataAndUserPosition(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()
	ta.startTokenSwapNotifier(ctx)
	contractAddress := "0xTEST0000000000000000000000000000000001"
	tokenExternalAddress := "0:test_token:"
	userExternalAddress := "0:test_user:"
	tokenType := TokenTypeProfile

	helperInsertTestUser(t, ctx, db, "test_creator", "creator", "Creator", "", true, PlatformGroupIonConnect)
	totalSupply, _ := big.NewInt(0).SetString("1000000000000000000000", 10) // 1000 tokens * 1e18
	burned, _ := big.NewInt(0).SetString("10000000000000000000", 10)        // 10 token * 1e18
	helperInsertTestToken(t, ctx, db,
		contractAddress,
		tokenExternalAddress,
		"TEST",
		tokenType,
		"test_creator",
		totalSupply.String(),
		0,
		0,
		0,
		PlatformGroupIonConnect,
	)

	helperInsertBaseTokenPrice(t, ctx, db, "0x2c73996babf1a06c2c057177353293f7ca0907c8", "ION", 0.01)

	t.Run("calculates_market_cap_correctly_for_buy", func(t *testing.T) {
		_ = testRedis.Del(ctx, keyUserPositionOfToken(tokenExternalAddress))
		_ = testRedis.Del(ctx, globalTopSetKey)
		_ = testRedis.Del(ctx, globalTopProfileSetKey)

		tx := &txEvent{
			TransactionHash: "0xtestbuy001",
			BlockNumber:     1,
			BlockTimestamp:  nil,
		}

		// Buy: user receives 10 tokens, price is $0.10 per token
		inputAmount := new(big.Int)
		inputAmount.SetString("1000000000000000000", 10) // 1 ION (or base token)
		outputAmount := new(big.Int)
		outputAmount.SetString("10000000000000000000", 10) // 10 tokens
		priceUSD := 0.10                                   // $0.10 per token
		direction := false

		mockBackend.SetBalanceOfResponse(outputAmount)
		helperInsertTokenSwap(t, t.Context(), ta.ingestedDataDB, contractAddress, tokenExternalAddress,
			"0x0000000000000000000000000000000000000000", tx.TransactionHash, false, inputAmount.String(), outputAmount.String(), priceUSD)

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx, "TEST", contractAddress, direction,
			inputAmount, outputAmount, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,                                              // platform
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		// = 0.10 * ((1000 - 10) * 1e18 / 1e18) = 0.10 * 1000 = 100.0
		expectedMarketCap := 172.5

		score, err := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		require.InDelta(t, expectedMarketCap, score, 0.001, "Market cap in globalTopSetKey should be 100.0")

		score, err = testRedis.ZScore(ctx, globalTopProfileSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		require.InDelta(t, expectedMarketCap, score, 0.001, "Market cap in globalTopProfileSetKey should be 100.0")

		userScore, err := testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		require.NoError(t, err)
		require.InDelta(t, 10.0, userScore, 0.001, "User should have 10 tokens")
	})

	t.Run("updates_market_cap_on_price_change", func(t *testing.T) {
		_ = testRedis.Del(ctx, keyUserPositionOfToken(tokenExternalAddress))
		_ = testRedis.Del(ctx, globalTopSetKey)

		tx := &txEvent{
			TransactionHash: "0xtestbuy002",
			BlockNumber:     2,
			BlockTimestamp:  nil,
		}

		// First swap: price $0.10
		inputAmount := new(big.Int)
		inputAmount.SetString("1000000000000000000", 10) // 1 ION
		outputAmount := new(big.Int)
		outputAmount.SetString("10000000000000000000", 10) // 10 tokens
		priceUSD := 0.10
		direction := false

		mockBackend.SetBalanceOfResponse(outputAmount)
		helperInsertTokenSwap(t, t.Context(), ta.ingestedDataDB, contractAddress, tokenExternalAddress,
			"0x0000000000000000000000000000000000000000", tx.TransactionHash, false, inputAmount.String(), outputAmount.String(), priceUSD)

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx, "TEST", contractAddress, direction,
			inputAmount, outputAmount, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,                                              // platform
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		score1, _ := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.InDelta(t, 172.5, score1, 0.001)

		// Second swap: price $0.20
		tx2 := &txEvent{
			TransactionHash: "0xtestbuy003",
			BlockNumber:     3,
			BlockTimestamp:  nil,
		}
		priceUSD2 := 0.20
		helperInsertTokenSwap(t, t.Context(), ta.ingestedDataDB, contractAddress, tokenExternalAddress,
			"0x0000000000000000000000000000000000000000", tx.TransactionHash, false, inputAmount.String(), outputAmount.String(), priceUSD2)

		err = ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx2, "TEST", contractAddress, direction,
			inputAmount, outputAmount, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		score2, err := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		require.InDelta(t, 172.5, score2, 0.001, "Market cap should double when price doubles")
	})

	t.Run("handles_sell_correctly", func(t *testing.T) {
		_ = testRedis.Del(ctx, keyUserPositionOfToken(tokenExternalAddress))
		_ = testRedis.Del(ctx, globalTopSetKey)

		// First: buy 20 tokens
		tx1 := &txEvent{
			TransactionHash: "0xtestbuy004",
			BlockNumber:     4,
		}
		buyInput := new(big.Int)
		buyInput.SetString("2000000000000000000", 10) // 2 ION
		buyOutput := new(big.Int)
		buyOutput.SetString("20000000000000000000", 10) // 20 tokens
		priceUSD := 0.10

		mockBackend.SetBalanceOfResponse(buyOutput)
		helperInsertTokenSwap(t, t.Context(), ta.ingestedDataDB, contractAddress, tokenExternalAddress,
			"0x0000000000000000000000000000000000000000", tx1.TransactionHash, false, buyInput.String(), buyOutput.String(), priceUSD)

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx1, "TEST", contractAddress, false,
			buyInput, buyOutput, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		userScore1, _ := testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		require.InDelta(t, 20.0, userScore1, 0.001)

		// Then: sell 5 tokens
		tx2 := &txEvent{
			TransactionHash: "0xtestsell001",
			BlockNumber:     5,
		}
		sellInput := new(big.Int)
		sellInput.SetString("5000000000000000000", 10) // 5 tokens (user sells)
		sellOutput := new(big.Int)
		sellOutput.SetString("500000000000000000", 10) // 0.5 ION (user receives)

		newPriceUSD := 0.05

		// After selling 5 tokens, user should have 15 tokens left
		remainingBalance := new(big.Int)
		remainingBalance.SetString("15000000000000000000", 10) // 15 tokens
		mockBackend.SetBalanceOfResponse(remainingBalance)
		helperInsertTokenSwap(t, t.Context(), ta.ingestedDataDB, contractAddress, tokenExternalAddress,
			"0x0000000000000000000000000000000000000000", tx2.TransactionHash, true, sellInput.String(), sellOutput.String(), newPriceUSD)

		err = ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx2, "TEST", contractAddress, true, // direction = true (sell)
			sellInput, sellOutput, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		userScore2, err := testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		require.NoError(t, err)
		require.InDelta(t, 15.0, userScore2, 0.001, "User position should be 15 tokens after selling 5")

		marketCapScore, err := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		// 0.5 * 172.5 * (1000 - 0) * 1e18 / 1e18
		require.InDelta(t, 172.5, marketCapScore, 0.001, "Market cap should decrease after sell due to lower price")
	})

	t.Run("removes_user_position_when_sold_all", func(t *testing.T) {
		_ = testRedis.Del(ctx, keyUserPositionOfToken(tokenExternalAddress))

		tx1 := &txEvent{TransactionHash: "0xtestbuy005"}
		buyInput := new(big.Int)
		buyInput.SetString("1000000000000000000", 10)
		buyOutput := new(big.Int)
		buyOutput.SetString("10000000000000000000", 10)

		mockBackend.SetBalanceOfResponse(buyOutput)

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx1, "TEST", contractAddress, false,
			buyInput, buyOutput, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		tx2 := &txEvent{TransactionHash: "0xtestsell002"}
		sellInput := new(big.Int)
		sellInput.SetString("10000000000000000000", 10)
		sellOutput := new(big.Int)
		sellOutput.SetString("1000000000000000000", 10)

		mockBackend.SetBalanceOfResponse(big.NewInt(0))

		err = ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx2, "TEST", contractAddress, true,
			sellInput, sellOutput, totalSupply, burned,
			tokenExternalAddress, userExternalAddress, tokenType,
			PlatformGroupIonConnect,
			"0x0000000000000000000000000000000000000000",                         // userBlockchainAddress
			"0x0000000000000000000000000000000000000000000000000000000000000001", // pairID
			"0x2c73996babf1a06c2c057177353293f7ca0907c8",                         // baseToken
			nil, nil,                                                             // baseProfileContractAddress, baseProfileExternalAddress
		)
		require.NoError(t, err)

		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		_, err = testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		require.Equal(t, redis.Nil, err, "User should be removed from position set when balance is 0")
	})
}
