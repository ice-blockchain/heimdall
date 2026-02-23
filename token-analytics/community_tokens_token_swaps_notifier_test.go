// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
)

func TestHandleTokenSwapUpdate(t *testing.T) {
	t.Run("processes token swap update and registers trade in QuestDB", func(t *testing.T) {
		ctx := context.Background()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		ionAddress := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		saveBaseTokenPriceToDatabase(ctx, db, "ION", ionAddress, 0.003, big.NewInt(3000000000000000))

		tokenExternalAddr := "0:test_swap_notifier:"
		contractAddr := "0x1111111111111111111111111111111111111111"
		userAddr := "0x2222222222222222222222222222222222222222"
		creatorPubkey := "creator_pubkey"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator", "Creator", contractAddr, false, PlatformGroupIonConnect)

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "TESTSN", "profile", contractAddr,
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr,
			"0x1234567890123456789012345678901234567890123456789012345678901234", ionAddress)

		txHash := "0xtest_swap_update_123"
		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExternalAddr, userAddr, txHash,
			true, "1000000000000000000", "100000000000000000", 0.005)

		userPubkey := "user_pubkey"
		helperInsertTestUser(t, ctx, db, userPubkey, "testuser", "Test User", userAddr, false, PlatformGroupIonConnect)

		helperInsertUserPosition(t, ctx, db, userAddr, contractAddr, tokenExternalAddr, helperBuildProfileExternalAddress(userPubkey), "1000000000000000000")

		update := tokenSwapUpdate{
			TransactionHash:       txHash,
			ContractAddress:       contractAddr,
			ExternalAddress:       tokenExternalAddr,
			UserBlockchainAddress: userAddr,
			Direction:             true,
			InputAmount:           "1000000000000000000",
			OutputAmount:          "100000000000000000",
			CurvePriceUSD:         0.005,
			CreatedAt:             stdlibtime.Now().Unix(),
			BaseToken:             ionAddress,
			TotalSupply:           "1000000000000000000000000",
			PairId:                "0x1234567890123456789012345678901234567890123456789012345678901234",
			Burned:                "0",
		}

		payload, err := json.Marshal(update)
		require.NoError(t, err)

		err = ta.handleTokenSwapUpdate(ctx, string(payload))
		require.NoError(t, err)

		type tradeResult struct {
			TransactionHash string  `db:"transaction_hash"`
			ContractAddress string  `db:"contract_address"`
			ExternalAddress string  `db:"external_address"`
			TraderAddress   string  `db:"trader_address"`
			TradeType       string  `db:"trade_type"`
			PriceInUsd      float64 `db:"price_in_usd"`
			MarketCapUsd    float64 `db:"market_cap_usd"`
			BaseAmount      string  `db:"base_amount"`
			Amount          string  `db:"amount"`
		}

		require.Eventually(t, func() bool {
			trades, err := questdb.Select[tradeResult](ctx, ta.questDB, `
				SELECT transaction_hash, contract_address, external_address, trader_address,
				       trade_type, price_in_usd, market_cap_usd, base_amount, amount
				FROM trades
				WHERE transaction_hash = $1
			`, txHash)
			if err != nil {
				return false
			}
			if len(trades) == 0 {
				return false
			}
			trade := trades[0]
			if trade.TransactionHash != txHash {
				return false
			}
			if trade.ContractAddress != contractAddr {
				return false
			}
			if trade.ExternalAddress != tokenExternalAddr {
				return false
			}
			if trade.TraderAddress != userAddr {
				return false
			}
			if trade.TradeType != "sell" {
				return false
			}
			if trade.PriceInUsd < 0.004 || trade.PriceInUsd > 0.006 {
				return false
			}
			if trade.MarketCapUsd <= 0.0 {
				return false
			}
			if trade.BaseAmount == "" || trade.Amount == "" {
				return false
			}
			return true
		}, 10*stdlibtime.Second, 200*stdlibtime.Millisecond, "registerTrade should have inserted complete trade into QuestDB")
	})

	t.Run("handles invalid JSON payload", func(t *testing.T) {
		ctx := context.Background()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		require.Error(t, ta.handleTokenSwapUpdate(ctx, "invalid json"))
	})

	t.Run("handles invalid input amount", func(t *testing.T) {
		ctx := context.Background()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		update := tokenSwapUpdate{
			TransactionHash:       "0xtest_invalid_amount",
			ContractAddress:       "0x1111111111111111111111111111111111111111",
			ExternalAddress:       "0:test:",
			UserBlockchainAddress: "0x2222222222222222222222222222222222222222",
			Direction:             true,
			InputAmount:           "invalid",
			OutputAmount:          "100000000000000000",
			CurvePriceUSD:         0.005,
			CreatedAt:             stdlibtime.Now().Unix(),
			BaseToken:             "0x2c73996babf1a06c2c057177353293f7ca0907c8",
			TotalSupply:           "1000000000000000000000000",
			PairId:                "0x1234567890123456789012345678901234567890123456789012345678901234",
			Burned:                "0",
		}

		payload, err := json.Marshal(update)
		require.NoError(t, err)

		require.Error(t, ta.handleTokenSwapUpdate(ctx, string(payload)))
	})

	t.Run("calculates market cap correctly with burned tokens", func(t *testing.T) {
		ctx := context.Background()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		ionAddress := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		saveBaseTokenPriceToDatabase(ctx, db, "ION", ionAddress, 0.003, big.NewInt(3000000000000000))

		tokenExternalAddr := "0:test_burned:"
		contractAddr := "0x3333333333333333333333333333333333333333"
		userAddr := "0x4444444444444444444444444444444444444444"
		creatorPubkey := "creator2_pubkey"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator2", "Creator2", contractAddr, false, PlatformGroupIonConnect)

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "TESTBURN", "profile", contractAddr,
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr,
			"0x1234567890123456789012345678901234567890123456789012345678901234", ionAddress)

		txHash := "0xtest_burned_123"
		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExternalAddr, userAddr, txHash,
			true, "1000000000000000000", "100000000000000000", 0.005)

		userPubkey := "user2_pubkey"
		helperInsertTestUser(t, ctx, db, userPubkey, "testuser2", "Test User 2", userAddr, false, PlatformGroupIonConnect)

		helperInsertUserPosition(t, ctx, db, userAddr, contractAddr, tokenExternalAddr, helperBuildProfileExternalAddress(userPubkey), "1000000000000000000")

		burnedAmount := "100000000000000000000000"
		update := tokenSwapUpdate{
			TransactionHash:       txHash,
			ContractAddress:       contractAddr,
			ExternalAddress:       tokenExternalAddr,
			UserBlockchainAddress: userAddr,
			Direction:             true,
			InputAmount:           "1000000000000000000",
			OutputAmount:          "100000000000000000",
			CurvePriceUSD:         0.005,
			CreatedAt:             stdlibtime.Now().Unix(),
			BaseToken:             ionAddress,
			TotalSupply:           "1000000000000000000000000",
			PairId:                "0x1234567890123456789012345678901234567890123456789012345678901234",
			Burned:                burnedAmount,
		}

		payload, err := json.Marshal(update)
		require.NoError(t, err)

		require.NoError(t, ta.handleTokenSwapUpdate(ctx, string(payload)))

		type tradeResult struct {
			TransactionHash string  `db:"transaction_hash"`
			ContractAddress string  `db:"contract_address"`
			ExternalAddress string  `db:"external_address"`
			TraderAddress   string  `db:"trader_address"`
			TradeType       string  `db:"trade_type"`
			PriceInUsd      float64 `db:"price_in_usd"`
			MarketCapUsd    float64 `db:"market_cap_usd"`
			BaseAmount      string  `db:"base_amount"`
			Amount          string  `db:"amount"`
		}

		require.Eventually(t, func() bool {
			trades, err := questdb.Select[tradeResult](ctx, ta.questDB, `
				SELECT transaction_hash, contract_address, external_address, trader_address,
				       trade_type, price_in_usd, market_cap_usd, base_amount, amount
				FROM trades
				WHERE transaction_hash = $1
			`, txHash)
			if err != nil {
				return false
			}
			if len(trades) == 0 {
				return false
			}

			trade := trades[0]
			if trade.TransactionHash != txHash {
				return false
			}
			if trade.ContractAddress != contractAddr {
				return false
			}
			if trade.ExternalAddress != tokenExternalAddr {
				return false
			}
			if trade.TraderAddress != userAddr {
				return false
			}
			if trade.TradeType != "sell" {
				return false
			}
			if trade.PriceInUsd < 0.004 || trade.PriceInUsd > 0.006 {
				return false
			}
			if trade.BaseAmount == "" || trade.Amount == "" {
				return false
			}

			expectedMarketCap := 0.005 * (1000000.0 - 100000.0)
			if trade.MarketCapUsd < expectedMarketCap-100.0 || trade.MarketCapUsd > expectedMarketCap+100.0 {
				return false
			}
			return true
		}, 10*stdlibtime.Second, 200*stdlibtime.Millisecond, "registerTrade should calculate market cap accounting for burned tokens")
	})
}
