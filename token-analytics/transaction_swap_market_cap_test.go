// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateTokenMarketDataAndUserPosition(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db).(*tokenAnalytics)

	contractAddress := "0xTEST0000000000000000000000000000000001"
	tokenExternalAddress := "0:test_token:"
	userExternalAddress := "0:test_user:"
	tokenType := TokenTypeProfile

	helperInsertTestUser(t, ctx, db, "test_creator", "creator", "Creator", "", true, PlatformGroupIonConnect)
	totalSupply := "1000000000000000000000" // 1000 tokens * 1e18
	helperInsertTestToken(t, ctx, db,
		contractAddress,
		tokenExternalAddress,
		"TEST",
		tokenType,
		"test_creator",
		totalSupply,
		0,
		0,
		0,
		PlatformGroupIonConnect,
	)

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

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx, contractAddress, direction,
			inputAmount, outputAmount, priceUSD,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)

		// = 0.10 * (1000 * 1e18 / 1e18) = 0.10 * 1000 = 100.0
		expectedMarketCap := 100.0

		score, err := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		assert.InDelta(t, expectedMarketCap, score, 0.001, "Market cap in globalTopSetKey should be 100.0")

		score, err = testRedis.ZScore(ctx, globalTopProfileSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		assert.InDelta(t, expectedMarketCap, score, 0.001, "Market cap in globalTopProfileSetKey should be 100.0")

		userScore, err := testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		require.NoError(t, err)
		assert.InDelta(t, 10.0, userScore, 0.001, "User should have 10 tokens")
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

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx, contractAddress, direction,
			inputAmount, outputAmount, priceUSD,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)

		score1, _ := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		assert.InDelta(t, 100.0, score1, 0.001)

		// Second swap: price $0.20
		tx2 := &txEvent{
			TransactionHash: "0xtestbuy003",
			BlockNumber:     3,
			BlockTimestamp:  nil,
		}
		priceUSD2 := 0.20

		err = ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx2, contractAddress, direction,
			inputAmount, outputAmount, priceUSD2,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)

		score2, err := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		assert.InDelta(t, 200.0, score2, 0.001, "Market cap should double when price doubles")
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

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx1, contractAddress, false,
			buyInput, buyOutput, priceUSD,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)

		userScore1, _ := testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		assert.InDelta(t, 20.0, userScore1, 0.001)

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
		err = ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx2, contractAddress, true, // direction = true (sell)
			sellInput, sellOutput, newPriceUSD,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)
		userScore2, err := testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		require.NoError(t, err)
		assert.InDelta(t, 15.0, userScore2, 0.001, "User position should be 15 tokens after selling 5")

		marketCapScore, err := testRedis.ZScore(ctx, globalTopSetKey, tokenExternalAddress).Result()
		require.NoError(t, err)
		assert.InDelta(t, 50.0, marketCapScore, 0.001, "Market cap should decrease after sell due to lower price")
	})

	t.Run("removes_user_position_when_sold_all", func(t *testing.T) {
		_ = testRedis.Del(ctx, keyUserPositionOfToken(tokenExternalAddress))

		tx1 := &txEvent{TransactionHash: "0xtestbuy005"}
		buyInput := new(big.Int)
		buyInput.SetString("1000000000000000000", 10)
		buyOutput := new(big.Int)
		buyOutput.SetString("10000000000000000000", 10)

		err := ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx1, contractAddress, false,
			buyInput, buyOutput, 0.10,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)

		tx2 := &txEvent{TransactionHash: "0xtestsell002"}
		sellInput := new(big.Int)
		sellInput.SetString("10000000000000000000", 10)
		sellOutput := new(big.Int)
		sellOutput.SetString("1000000000000000000", 10)

		err = ta.calculateTokenMarketDataAndUserPosition(
			ctx, tx2, contractAddress, true,
			sellInput, sellOutput, 0.10,
			tokenExternalAddress, userExternalAddress, tokenType, totalSupply,
		)
		require.NoError(t, err)

		_, err = testRedis.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddress), userExternalAddress).Result()
		assert.Equal(t, redis.Nil, err, "User should be removed from position set when balance is 0")
	})
}
