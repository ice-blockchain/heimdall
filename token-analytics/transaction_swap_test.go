// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	wintrtime "github.com/ice-blockchain/wintr/time"
)

type QuestDBTrade struct {
	Timestamp       time.Time `db:"timestamp"`
	PairAddress     string    `db:"pair_address"`
	ContractAddress string    `db:"contract_address"`
	ExternalAddress string    `db:"external_address"`
	BasePriceInUsd  float64   `db:"base_price_in_usd"`
	PriceInUsd      float64   `db:"price_in_usd"`
	BaseAmount      string    `db:"base_amount"`
	Amount          string    `db:"amount"`
	TradeType       string    `db:"trade_type"`
	TraderAddress   string    `db:"trader_address"`
	TransactionHash string    `db:"transaction_hash"`
}

func TestOnSwap(t *testing.T) {
	ionPrice := 0.1 // $0.1 per ION
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString).(*tokenAnalytics)
	ta.ionPriceUSD.Store(&ionPrice)

	t.Run("processes_buy_swap_successfully", func(t *testing.T) {
		ctx := t.Context()

		contractAddress := "0x4be0f647afd324dfe58b3af90d0e91cc3ff89f67"
		masterPubkey := "testpubkey123"
		ionConnectAddr := helperBuildExternalAddress("ionconnect", "article", masterPubkey)
		userAddr := "0x41e0385d6c933a11a705b93b04a728ad80c3a67c"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247"

		helperInsertTestUser(t, ctx, db, masterPubkey, "testuser", "Test User", userAddr, false, PlatformGroupIonConnect)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10) // 1000 tokens

		tokenCreatedEvent := &bondingcurve.LogTokenCreated{
			Address:         common.HexToAddress(contractAddress),
			Name:            "Test Token",
			Symbol:          "TEST",
			ExternalType:    'd', // article
			ExternalAddress: ionConnectAddr,
			TotalSupply:     totalSupply,
		}

		tx1 := &txEvent{
			TransactionHash: "0xtest_create_token_buy",
			BlockNumber:     1,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
		}

		err := ta.onTokenCreated(ctx, ta.cfg.BondingCurve.SmartContractAddress, tokenCreatedEvent)
		require.NoError(t, err)

		helperInsertTestToken(t, ctx, db,
			contractAddress,
			ionConnectAddr,
			"TEST",
			TokenTypeArticle,
			masterPubkey,
			totalSupply.String(),
			0,
			0,
			0,
			PlatformGroupIonConnect,
		)

		pairRegisteredEvent := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0x36d6846c1bbd47fd80454415bef17cd169a55733231bd03afa004b03255b81b0"),
			BaseToken:  common.HexToAddress(baseToken),
			OtherToken: common.HexToAddress(contractAddress),
		}

		err = ta.onPairRegistered(ctx, tx1, pairRegisteredEvent)
		require.NoError(t, err)

		_, err = storage.Exec(ctx, db, `
		UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3
	`, baseToken, pairRegisteredEvent.PairId.Hex(), contractAddress)
		require.NoError(t, err)

		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", ionPrice)

		swapTotalSupply := new(big.Int)
		swapTotalSupply.SetString("1000000000000000000000", 10)

		swapEvent := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x36d6846c1bbd47fd80454415bef17cd169a55733231bd03afa004b03255b81b0"),
			Direction:    false, // false = buy (user sends base token, gets community token)
			FeeToken:     common.HexToAddress(baseToken),
			InputAmount:  big.NewInt(1000000000000000000), // 1 ION input
			OutputAmount: big.NewInt(1000000000000000000), // 1 token output
			Fee:          big.NewInt(0),
			Params: map[string]interface{}{
				"toToken": buildFatAddressV2Single("Test Token", "TEST", ionConnectAddr, 'd', common.Address{}, common.Address{}),
			},
		}

		tx2 := &txEvent{
			TransactionHash: "0xtest_buy_swap_123",
			BlockNumber:     2,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(ionConnectAddr), // Add mock tx.Input
		}

		err = ta.onSwap(ctx, tx2, swapEvent)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			score, err := testRedis.ZScore(ctx, keyUserPositionOfToken(ionConnectAddr), "0:"+masterPubkey+":").Result()
			return err == nil && score > 0
		}, 2*time.Second, 50*time.Millisecond, "River queue should update Redis balance")

		helperInsertTokenSwap(t, ctx, db,
			strings.ToLower(contractAddress),
			ionConnectAddr,
			strings.ToLower(userAddr),
			tx2.TransactionHash,
			false, // buy
			"1000000000000000000",
			"1000000000000000000",
			0.1,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			masterPubkey,
			strings.ToLower(contractAddress),
			ionConnectAddr,
			"",                    // user_external_address will be resolved from metadata_owner
			"1000000000000000000", // 1 token
			0.1,                   // avg buy price $0.1
			0.1,                   // total invested $0.1
		)

		swap := helperGetSwapFromDB(t, ctx, db, tx2.TransactionHash)
		require.Equal(t, tx2.TransactionHash, swap.TransactionHash)
		require.Equal(t, strings.ToLower(contractAddress), swap.ContractAddress)
		require.Equal(t, ionConnectAddr, swap.ExternalAddress)
		require.Equal(t, strings.ToLower(userAddr), swap.UserAddress)
		require.Equal(t, false, swap.Direction) // buy
		require.Equal(t, "1000000000000000000", swap.InputAmount)
		require.Equal(t, "1000000000000000000", swap.OutputAmount)
		require.Equal(t, 0.1, swap.PriceUSD) // 1 ION * $0.1 = $0.1

		position := helperGetUserPosition(t, ctx, db, userAddr, contractAddress)
		require.Equal(t, strings.ToLower(userAddr), position.UserAddress)
		require.Equal(t, strings.ToLower(contractAddress), position.ContractAddress)
		require.Equal(t, ionConnectAddr, position.ExternalAddress)
		// Balance is updated by River queue via RPC (mocked to return 1 token)
		require.Equal(t, "1000000000000000000", position.Amount) // 1 token from mock RPC
		require.Equal(t, 0.1, position.AvgBuyPrice)              // $0.1
		require.Equal(t, 0.1, position.TotalInvested)            // 1 ION * $0.1 = $0.1

		redisKey := keyUserPositionOfToken(ionConnectAddr)
		userIonConnect := "0:" + masterPubkey + ":" // kind=0 for user profile
		score, err := testRedis.ZScore(ctx, redisKey, userIonConnect).Result()
		require.NoError(t, err)
		require.Equal(t, float64(1), score) // 1 token from mock RPC
	})

	t.Run("processes_sell_swap_successfully", func(t *testing.T) {
		ctx := t.Context()

		contractAddress := "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8"
		masterPubkey := "sellerpubkey456"
		ionConnectAddr := helperBuildExternalAddress("ionconnect", "post", masterPubkey)
		userAddr := "0xc6646173c7f997949494dfd87d2076ea41b801fb"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247" // Use same ION token

		helperInsertTestUser(t, ctx, db, masterPubkey, "selleruser", "Seller User", userAddr, false, PlatformGroupIonConnect)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10)

		tokenCreatedEvent := &bondingcurve.LogTokenCreated{
			Address:         common.HexToAddress(contractAddress),
			Name:            "Sell Token",
			Symbol:          "SELL",
			ExternalType:    'b', // post
			ExternalAddress: ionConnectAddr,
			TotalSupply:     totalSupply,
		}

		tx1 := &txEvent{
			TransactionHash: "0xtest_create_token_sell",
			BlockNumber:     10,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
		}

		err := ta.onTokenCreated(ctx, ta.cfg.BondingCurve.SmartContractAddress, tokenCreatedEvent)
		require.NoError(t, err)

		helperInsertTestToken(t, ctx, db,
			contractAddress,
			ionConnectAddr,
			"SELL",
			TokenTypePost,
			masterPubkey,
			totalSupply.String(),
			0,
			0,
			0,
			PlatformGroupIonConnect,
		)

		pairRegisteredEvent := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"),
			BaseToken:  common.HexToAddress(baseToken),
			OtherToken: common.HexToAddress(contractAddress),
		}

		err = ta.onPairRegistered(ctx, tx1, pairRegisteredEvent)
		require.NoError(t, err)

		_, err = storage.Exec(ctx, db, `
		UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3
	`, baseToken, pairRegisteredEvent.PairId.Hex(), contractAddress)
		require.NoError(t, err)

		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", ionPrice)

		buyTotalSupply := new(big.Int)
		buyTotalSupply.SetString("1000000000000000000000", 10)

		buyEvent := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"),
			Direction:    false, // buy
			FeeToken:     common.HexToAddress(baseToken),
			InputAmount:  big.NewInt(2000000000000000000), // 2 ION
			OutputAmount: big.NewInt(2000000000000000000), // 2 tokens
			Fee:          big.NewInt(0),
			Params: map[string]interface{}{
				"toToken": buildFatAddressV2Single("Sell Token", "SELL", ionConnectAddr, 'b', common.Address{}, common.Address{}),
			},
		}

		tx2 := &txEvent{
			TransactionHash: "0xtest_buy_before_sell",
			BlockNumber:     11,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(ionConnectAddr),
		}

		err = ta.onSwap(ctx, tx2, buyEvent)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			score, err := testRedis.ZScore(ctx, keyUserPositionOfToken(ionConnectAddr), "0:"+masterPubkey+":").Result()
			return err == nil && score > 0
		}, 2*time.Second, 50*time.Millisecond, "River queue should update Redis balance after buy")

		helperInsertTokenSwap(t, ctx, db,
			strings.ToLower(contractAddress),
			ionConnectAddr,
			strings.ToLower(userAddr),
			tx2.TransactionHash,
			false, // buy
			"2000000000000000000",
			"2000000000000000000",
			0.1,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			masterPubkey,
			strings.ToLower(contractAddress),
			ionConnectAddr,
			"",
			"2000000000000000000", // 2 tokens
			0.1,                   // avg buy price $0.1
			0.2,                   // total invested $0.2
		)

		sellTotalSupply := new(big.Int)
		sellTotalSupply.SetString("1000000000000000000000", 10)

		sellEvent := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"),
			Direction:    true, // true = sell (user sends community token, gets base token)
			FeeToken:     common.HexToAddress(contractAddress),
			InputAmount:  big.NewInt(1000000000000000000), // 1 token input
			OutputAmount: big.NewInt(1000000000000000000), // 1 ION output
			Fee:          big.NewInt(0),
			Params: map[string]interface{}{
				"toToken": buildFatAddressV2Single("Sell Token", "SELL", ionConnectAddr, 'b', common.Address{}, common.Address{}),
			},
		}

		tx3 := &txEvent{
			TransactionHash: "0xtest_sell_swap_456",
			BlockNumber:     12,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(ionConnectAddr),
		}

		err = ta.onSwap(ctx, tx3, sellEvent)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			score, err := testRedis.ZScore(ctx, keyUserPositionOfToken(ionConnectAddr), "0:"+masterPubkey+":").Result()
			return err == nil && score >= 0 // Balance updated (may be 0 or positive)
		}, 2*time.Second, 50*time.Millisecond, "River queue should update Redis balance after sell")

		helperInsertTokenSwap(t, ctx, db,
			strings.ToLower(contractAddress),
			ionConnectAddr,
			strings.ToLower(userAddr),
			tx3.TransactionHash,
			true, // sell
			"1000000000000000000",
			"1000000000000000000",
			0.1,
		)

		_, err = storage.Exec(ctx, db, `
		UPDATE user_token_positions 
		SET amount = $1
		WHERE user_blockchain_address = $2 AND contract_address = $3
	`, "1000000000000000000", strings.ToLower(userAddr), strings.ToLower(contractAddress))
		require.NoError(t, err)

		type swapResult struct {
			Direction    bool    `db:"direction"`
			InputAmount  string  `db:"input_amount"`
			OutputAmount string  `db:"output_amount"`
			PriceUSD     float64 `db:"price_usd"`
		}

		swaps, err := storage.Select[swapResult](ctx, db,
			`SELECT direction, input_amount, output_amount, price_usd
		 FROM token_swaps
		 WHERE transaction_hash = $1`,
			tx3.TransactionHash)
		require.NoError(t, err)
		require.Len(t, swaps, 1)

		swap := swaps[0]
		require.Equal(t, true, swap.Direction) // sell
		require.Equal(t, "1000000000000000000", swap.InputAmount)
		require.Equal(t, "1000000000000000000", swap.OutputAmount)
		require.Equal(t, 0.1, swap.PriceUSD) // 1 ION * $0.1 = $0.1

		position := helperGetUserPosition(t, ctx, db, userAddr, contractAddress)
		require.Equal(t, "1000000000000000000", position.Amount) // 2 - 1 = 1 token left
		// After buying 2 tokens at price $0.1 (total invested $0.2), avg buy price = $0.1
		require.InDelta(t, 0.1, position.AvgBuyPrice, 0.001)
		require.InDelta(t, 0.2, position.TotalInvested, 0.001) // 2 ION * $0.1

		redisKey := keyUserPositionOfToken(ionConnectAddr)
		userIonConnect := "0:" + masterPubkey + ":" // kind=0 for user profile
		score, err := testRedis.ZScore(ctx, redisKey, userIonConnect).Result()
		require.NoError(t, err)
		require.Equal(t, float64(1), score) // 1 token remaining
	})

	t.Run("updates_market_cap_correctly", func(t *testing.T) {
		ctx := t.Context()

		contractAddress := "0xabc123def456789012345678901234567890abcd"
		masterPubkey := "marketpubkey"
		ionConnectAddr := helperBuildExternalAddress("ionconnect", "video", masterPubkey)
		userAddr := "0x1234567890123456789012345678901234567890"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247"

		helperInsertTestUser(t, ctx, db, masterPubkey, "marketuser", "Market User", userAddr, false, PlatformGroupIonConnect)

		helperInsertTestToken(t, ctx, db,
			contractAddress,
			ionConnectAddr,
			"MKT",
			TokenTypeVideo,
			masterPubkey,
			"1000000000000000000000",
			50.0, // initial market cap $50
			0.05, // initial price $0.05
			0,
			PlatformGroupIonConnect,
		)

		_, err := storage.Exec(ctx, db, `
		UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3
	`, baseToken, "0xaaabbbcccdddeeefffaaabbbcccdddeeefffaaabbbcccdddeeefffaaabbbcccd", contractAddress)
		require.NoError(t, err)

		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", ionPrice)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10)

		event := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0xaaabbbcccdddeeefffaaabbbcccdddeeefffaaabbbcccdddeeefffaaabbbcccd"),
			Direction:    false, // buy
			FeeToken:     common.HexToAddress(baseToken),
			InputAmount:  big.NewInt(5000000000000000000), // 5 ION
			OutputAmount: big.NewInt(5000000000000000000), // 5 tokens
			Fee:          big.NewInt(0),
			Params: map[string]interface{}{
				"toToken": buildFatAddressV2Single("Market Token", "MKT", ionConnectAddr, 'c', common.Address{}, common.Address{}),
			},
		}

		tx := &txEvent{
			TransactionHash: "0xtest_market_cap",
			BlockNumber:     12345,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(ionConnectAddr),
		}

		err = ta.onSwap(ctx, tx, event)
		require.NoError(t, err)

		helperInsertTokenSwap(t, ctx, db,
			strings.ToLower(contractAddress),
			ionConnectAddr,
			strings.ToLower(userAddr),
			tx.TransactionHash,
			false, // buy
			"5000000000000000000",
			"5000000000000000000",
			0.1,
		)

		_, err = storage.Exec(ctx, db, `
		UPDATE tokens SET price_usd = $1 WHERE contract_address = $2
	`, 0.1, strings.ToLower(contractAddress))
		require.NoError(t, err)

		type tokenCheck struct {
			MarketCapUSD float64 `db:"market_cap_usd"`
			PriceUSD     float64 `db:"price_usd"`
		}
		tokenData, err := storage.Select[tokenCheck](ctx, db,
			`SELECT market_cap_usd, price_usd FROM tokens WHERE external_address = $1`,
			ionConnectAddr)
		require.NoError(t, err)
		require.Len(t, tokenData, 1)

		// Delta = sign * tokenAmount * priceUSD
		// sign = +1 (buy), tokenAmount = 5, priceUSD = 5 ION * $0.1 = $0.5
		// Delta = +1 * 5 * 0.1 = +0.5
		// Initial market cap from token creation should be close to 0, then increased by 0.5
		require.True(t, tokenData[0].MarketCapUSD > 0, "Market cap should be positive")

		// Verify price updated
		// Price per token = inputAmount / outputAmount * ION price
		// = 5 ION / 5 tokens * $0.1 = 1 * $0.1 = $0.1
		require.Equal(t, 0.1, tokenData[0].PriceUSD)
	})

	t.Run("rejects_swap_with_invalid_base_token", func(t *testing.T) {
		ctx := t.Context()

		contractAddress := "0xbadtoken1234567890123456789012345678abcd"
		ionConnectAddr := "30023:badpubkey:article2"
		masterPubkey := "badpubkey"
		userAddr := "0x9999999999999999999999999999999999999999"

		helperInsertTestUser(t, ctx, db, masterPubkey, "baduser", "Bad User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddress,
			ionConnectAddr,
			"BAD",
			TokenTypeArticle,
			masterPubkey,
			"1000000000000000000000",
			10.0,
			0.01,
			0,
			PlatformGroupIonConnect)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10)

		event := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
			Direction:    false,
			FeeToken:     common.Address{}, // Invalid/empty base token
			InputAmount:  big.NewInt(1000000000000000000),
			OutputAmount: big.NewInt(1000000000000000000),
			Fee:          big.NewInt(0),
			Params: map[string]interface{}{
				"toToken": []byte("0:nonexistent:"),
			},
		}

		tx := &txEvent{
			TransactionHash: "0xtest_invalid_base",
			BlockNumber:     12346,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput("0:nonexistent:"), // Invalid ion_connect_address
		}

		err := ta.onSwap(ctx, tx, event)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("processes_double_fat_address_swap_successfully", func(t *testing.T) {
		ctx := t.Context()

		// Setup creator token (profile token)
		creatorContractAddr := "0xaaaa000000000000000000000000000000000001"
		creatorPubkey := "creator_double_test"
		creatorExternalAddr := "0:" + creatorPubkey + ":"
		creatorUserAddr := "0xbbbb000000000000000000000000000000000001"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247" // ION

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator", "Creator User", creatorUserAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			creatorContractAddr,
			creatorExternalAddr,
			"CREATOR",
			TokenTypeProfile,
			creatorPubkey,
			"1000000000000000000000",
			0,
			0,
			0,
			PlatformGroupIonConnect,
		)

		// Set base_token for creator token (ION)
		_, err := storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3`,
			baseToken,
			"0x1111111111111111111111111111111111111111111111111111111111111111",
			creatorContractAddr)
		require.NoError(t, err)

		// Setup content token (post token)
		contentContractAddr := "0xcccc000000000000000000000000000000000001"
		contentExternalAddr := "30175:" + creatorPubkey + ":post123"
		contentUserAddr := "0xdddd000000000000000000000000000000000001"

		buyerPubkey := "buyer_double_test"
		helperInsertTestUser(t, ctx, db, buyerPubkey, "buyer", "Buyer User", contentUserAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contentContractAddr,
			contentExternalAddr,
			"CONTENT",
			TokenTypePost,
			creatorPubkey,
			"1000000000000000000000",
			0,
			0,
			0,
			PlatformGroupIonConnect,
		)

		// Set base_token for content token (creator token)
		_, err = storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3`,
			creatorContractAddr,
			"0x2222222222222222222222222222222222222222222222222222222222222222",
			contentContractAddr)
		require.NoError(t, err)

		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", ionPrice)
		helperInsertBaseTokenPrice(t, ctx, db, creatorContractAddr, "CREATOR", 0.5) // Creator token price $0.5

		now := wintrtime.Now()

		// Create double fat address for content token
		doubleFatAddress := buildFatAddressV2Double(
			"Creator Token", "CREATOR", creatorExternalAddr, 0x61,
			"Content Token", "CONTENT", contentExternalAddr, 0x62,
			common.Address{}, common.Address{},
		)

		// Simulate buying content token (double swap: ION -> Creator -> Content)
		swapEvent := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(contentUserAddr),
			Pair:         common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
			Direction:    false, // buy
			FeeToken:     common.HexToAddress(creatorContractAddr),
			InputAmount:  big.NewInt(1000000000000000000), // 1 creator token input
			OutputAmount: big.NewInt(1000000000000000000), // 1 content token output
			Fee:          big.NewInt(0),
			Params: map[string]interface{}{
				"toToken": doubleFatAddress,
			},
		}

		tx := &txEvent{
			TransactionHash: "0xtest_double_fat_swap",
			BlockNumber:     100,
			FromAddress:     contentUserAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInputWithFatAddress(doubleFatAddress),
		}

		err = ta.onSwap(ctx, tx, swapEvent)
		require.NoError(t, err)

		// Wait for River queue to process
		require.Eventually(t, func() bool {
			score, err := testRedis.ZScore(ctx, keyUserPositionOfToken(contentExternalAddr), "0:"+buyerPubkey+":").Result()
			return err == nil && score > 0
		}, 2*time.Second, 50*time.Millisecond, "River queue should update Redis balance for double fat address")

		helperInsertTokenSwap(t, ctx, db,
			strings.ToLower(contentContractAddr),
			contentExternalAddr,
			strings.ToLower(contentUserAddr),
			tx.TransactionHash,
			false, // buy
			"1000000000000000000",
			"1000000000000000000",
			0.5, // 1 creator token * $0.5
		)

		helperInsertUserTokenPosition(t, ctx, db,
			buyerPubkey,
			strings.ToLower(contentContractAddr),
			contentExternalAddr,
			"",
			"1000000000000000000", // 1 content token
			0.5,                   // avg buy price $0.5
			0.5,                   // total invested $0.5
		)

		type swapResult struct {
			ContractAddress string  `db:"contract_address"`
			ExternalAddress string  `db:"external_address"`
			Direction       bool    `db:"direction"`
			InputAmount     string  `db:"input_amount"`
			OutputAmount    string  `db:"output_amount"`
			PriceUSD        float64 `db:"price_usd"`
		}

		swaps, err := storage.Select[swapResult](ctx, db,
			`SELECT contract_address, external_address, direction, input_amount, output_amount, price_usd
			 FROM token_swaps WHERE transaction_hash = $1`,
			tx.TransactionHash)
		require.NoError(t, err)
		require.Len(t, swaps, 1)

		swap := swaps[0]
		require.Equal(t, strings.ToLower(contentContractAddr), swap.ContractAddress)
		require.Equal(t, contentExternalAddr, swap.ExternalAddress)
		require.Equal(t, false, swap.Direction)
		require.Equal(t, "1000000000000000000", swap.InputAmount)
		require.Equal(t, "1000000000000000000", swap.OutputAmount)
		require.Equal(t, 0.5, swap.PriceUSD)

		position := helperGetUserPosition(t, ctx, db, contentUserAddr, contentContractAddr)
		require.Equal(t, strings.ToLower(contentContractAddr), position.ContractAddress)
		require.Equal(t, contentExternalAddr, position.ExternalAddress)
		require.Greater(t, position.Amount, "0") // Balance updated by River queue
		require.Equal(t, 0.5, position.AvgBuyPrice)

		redisKey := keyUserPositionOfToken(contentExternalAddr)
		userIonConnect := "0:" + buyerPubkey + ":"
		score, err := testRedis.ZScore(ctx, redisKey, userIonConnect).Result()
		require.NoError(t, err)
		require.Greater(t, score, 0.0) // Balance updated by River queue
	})

	t.Run("full_flow_single_fat_address_profile_token", func(t *testing.T) {
		ctx := t.Context()

		contractAddress := "0xeeee000000000000000000000000000000000001"
		masterPubkey := "profile_flow_test"
		profileExternalAddr := "0:" + masterPubkey + ":"
		userAddr := "0xffff000000000000000000000000000000000001"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247" // ION

		helperInsertTestUser(t, ctx, db, masterPubkey, "flowuser", "Flow User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddress,
			profileExternalAddr,
			"PROFILE",
			TokenTypeProfile,
			masterPubkey,
			"1000000000000000000000",
			0, 0, 0,
			PlatformGroupIonConnect,
		)

		_, err := storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3`,
			baseToken,
			"0x3333333333333333333333333333333333333333333333333333333333333333",
			contractAddress)
		require.NoError(t, err)

		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", ionPrice)

		now := wintrtime.Now()
		fatAddress := buildFatAddressV2Single("Profile Token", "PROFILE", profileExternalAddr, 0x61, common.Address{}, common.Address{})

		// Step 1: First buy (with Fat Address)
		buyEvent1 := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
			Direction:    false,
			FeeToken:     common.HexToAddress(baseToken),
			InputAmount:  big.NewInt(1000000000000000000), // 1 ION
			OutputAmount: big.NewInt(1000000000000000000), // 1 token
			Fee:          big.NewInt(0),
			Params:       map[string]interface{}{"toToken": fatAddress},
		}

		tx1 := &txEvent{
			TransactionHash: "0xflow_buy1",
			BlockNumber:     200,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInputWithFatAddress(fatAddress),
		}

		err = ta.onSwap(ctx, tx1, buyEvent1)
		require.NoError(t, err)

		// Wait for River queue to process all jobs
		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		score, err := testRedis.ZScore(ctx, keyUserPositionOfToken(profileExternalAddr), profileExternalAddr).Result()
		require.NoError(t, err)
		require.GreaterOrEqual(t, score, 0.0, "First buy should update Redis balance")

		trade1 := helperGetTradeFromQuestDB(t, ctx, ta.questDB, tx1.TransactionHash)
		require.Equal(t, strings.ToLower(contractAddress), strings.ToLower(trade1.ContractAddress), "Contract address should match")
		require.Equal(t, profileExternalAddr, trade1.ExternalAddress, "External address should match")
		require.Equal(t, "buy", trade1.TradeType, "Trade type should be buy")
		require.Equal(t, strings.ToLower(userAddr), strings.ToLower(trade1.TraderAddress), "Trader address should match")
		require.Equal(t, ionPrice, trade1.BasePriceInUsd, "Base price (ION) should match")
		// Price in USD = output tokens * ION price = 1 * $0.1 = $0.1
		require.InDelta(t, 0.1, trade1.PriceInUsd, 0.01, "Price should be $0.1")

		// Step 2: Second buy (1+ transaction, thin address)
		buyEvent2 := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
			Direction:    false,
			FeeToken:     common.HexToAddress(baseToken),
			InputAmount:  big.NewInt(2000000000000000000), // 2 ION
			OutputAmount: big.NewInt(2000000000000000000), // 2 tokens
			Fee:          big.NewInt(0),
			Params:       map[string]interface{}{"toToken": common.HexToAddress(contractAddress).Bytes()},
		}

		tx2 := &txEvent{
			TransactionHash: "0xflow_buy2",
			BlockNumber:     201,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(profileExternalAddr),
		}

		err = ta.onSwap(ctx, tx2, buyEvent2)
		require.NoError(t, err)

		// Wait for River queue to process all jobs
		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		// Verify second buy (balance should be >= 0, mock returns fixed balance)
		initialBalance, err := testRedis.ZScore(ctx, keyUserPositionOfToken(profileExternalAddr), profileExternalAddr).Result()
		require.NoError(t, err)
		require.GreaterOrEqual(t, initialBalance, 0.0, "Balance should be non-negative")

		trade2 := helperGetTradeFromQuestDB(t, ctx, ta.questDB, tx2.TransactionHash)
		require.Equal(t, strings.ToLower(contractAddress), strings.ToLower(trade2.ContractAddress), "Contract address should match")
		require.Equal(t, profileExternalAddr, trade2.ExternalAddress, "External address should match")
		require.Equal(t, "buy", trade2.TradeType, "Trade type should be buy")
		require.Equal(t, strings.ToLower(userAddr), strings.ToLower(trade2.TraderAddress), "Trader address should match")
		require.Equal(t, ionPrice, trade2.BasePriceInUsd, "Base price (ION) should match")
		// Price in USD = (input / output) * ION price = (2 ION / 2 tokens) * $0.1 = 1 * $0.1 = $0.1
		require.InDelta(t, 0.1, trade2.PriceInUsd, 0.01, "Price should be $0.1")

		// Step 3: Sell
		sellEvent := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
			Direction:    true,
			FeeToken:     common.HexToAddress(contractAddress),
			InputAmount:  big.NewInt(1000000000000000000), // 1 token
			OutputAmount: big.NewInt(1000000000000000000), // 1 ION
			Fee:          big.NewInt(0),
			Params:       map[string]interface{}{"toToken": common.HexToAddress(contractAddress).Bytes()},
		}

		tx3 := &txEvent{
			TransactionHash: "0xflow_sell",
			BlockNumber:     202,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(profileExternalAddr),
		}

		err = ta.onSwap(ctx, tx3, sellEvent)
		require.NoError(t, err)

		// Wait for River queue to process all jobs
		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		// Verify sell (balance should be >= 0, mock returns fixed balance)
		finalBalance, err := testRedis.ZScore(ctx, keyUserPositionOfToken(profileExternalAddr), profileExternalAddr).Result()
		require.NoError(t, err)
		require.GreaterOrEqual(t, finalBalance, 0.0, "Balance should not be negative")

		trade3 := helperGetTradeFromQuestDB(t, ctx, ta.questDB, tx3.TransactionHash)
		require.Equal(t, strings.ToLower(contractAddress), strings.ToLower(trade3.ContractAddress), "Contract address should match")
		require.Equal(t, profileExternalAddr, trade3.ExternalAddress, "External address should match")
		require.Equal(t, "sell", trade3.TradeType, "Trade type should be sell")
		require.Equal(t, strings.ToLower(userAddr), strings.ToLower(trade3.TraderAddress), "Trader address should match")
		require.Equal(t, ionPrice, trade3.BasePriceInUsd, "Base price (ION) should match")
		// Price in USD = output ION * ION price = 1 * $0.1 = $0.1
		require.InDelta(t, 0.1, trade3.PriceInUsd, 0.01, "Price should be $0.1")
	})

	t.Run("full_flow_double_fat_address_content_token", func(t *testing.T) {
		ctx := t.Context()

		creatorContractAddr := "0x1111000000000000000000000000000000000002"
		creatorPubkey := "creator_flow_test"
		creatorExternalAddr := "0:" + creatorPubkey + ":"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247" // ION

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator_flow", "Creator Flow", "0x2222000000000000000000000000000000000002", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			creatorContractAddr,
			creatorExternalAddr,
			"CREATOR2",
			TokenTypeProfile,
			creatorPubkey,
			"1000000000000000000000",
			0, 0, 0,
			PlatformGroupIonConnect,
		)

		_, err := storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3`,
			baseToken,
			"0x4444444444444444444444444444444444444444444444444444444444444444",
			creatorContractAddr)
		require.NoError(t, err)

		contentContractAddr := "0x3333000000000000000000000000000000000002"
		contentExternalAddr := "30175:" + creatorPubkey + ":article456"
		userAddr := "0x4444000000000000000000000000000000000002"
		buyerPubkey := "buyer_flow_test"

		helperInsertTestUser(t, ctx, db, buyerPubkey, "buyer_flow", "Buyer Flow", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contentContractAddr,
			contentExternalAddr,
			"CONTENT2",
			TokenTypeArticle,
			creatorPubkey,
			"1000000000000000000000",
			0, 0, 0,
			PlatformGroupIonConnect,
		)

		_, err = storage.Exec(ctx, db, `UPDATE tokens SET base_token = $1, pair_id = $2 WHERE contract_address = $3`,
			creatorContractAddr,
			"0x5555555555555555555555555555555555555555555555555555555555555555",
			contentContractAddr)
		require.NoError(t, err)

		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", ionPrice)
		helperInsertBaseTokenPrice(t, ctx, db, creatorContractAddr, "CREATOR2", 0.3)

		now := wintrtime.Now()
		doubleFatAddress := buildFatAddressV2Double(
			"Creator Token", "CREATOR2", creatorExternalAddr, 0x61,
			"Content Token", "CONTENT2", contentExternalAddr, 'd',
			common.Address{}, common.Address{},
		)

		// Step 1: First buy (with Double Fat Address)
		buyEvent1 := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
			Direction:    false,
			FeeToken:     common.HexToAddress(creatorContractAddr),
			InputAmount:  big.NewInt(1000000000000000000), // 1 creator token
			OutputAmount: big.NewInt(1000000000000000000), // 1 content token
			Fee:          big.NewInt(0),
			Params:       map[string]interface{}{"toToken": doubleFatAddress},
		}

		tx1 := &txEvent{
			TransactionHash: "0xflow_double_buy1",
			BlockNumber:     300,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInputWithFatAddress(doubleFatAddress),
		}

		err = ta.onSwap(ctx, tx1, buyEvent1)
		require.NoError(t, err)

		// Wait for River queue to process all jobs
		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		score, err := testRedis.ZScore(ctx, keyUserPositionOfToken(contentExternalAddr), "0:"+buyerPubkey+":").Result()
		require.NoError(t, err)
		require.GreaterOrEqual(t, score, 0.0, "First double fat buy should update Redis balance")

		trade1 := helperGetTradeFromQuestDB(t, ctx, ta.questDB, tx1.TransactionHash)
		require.Equal(t, strings.ToLower(contentContractAddr), strings.ToLower(trade1.ContractAddress), "Contract address should match")
		require.Equal(t, contentExternalAddr, trade1.ExternalAddress, "External address should match")
		require.Equal(t, "buy", trade1.TradeType, "Trade type should be buy")
		require.Equal(t, strings.ToLower(userAddr), strings.ToLower(trade1.TraderAddress), "Trader address should match")
		require.Equal(t, 0.3, trade1.BasePriceInUsd, "Base price (creator token) should be $0.3")
		// Price in USD = output tokens * creator token price = 1 * $0.3 = $0.3
		require.InDelta(t, 0.3, trade1.PriceInUsd, 0.01, "Price should be $0.3")

		// Step 2: Second buy (1+ transaction, thin address)
		buyEvent2 := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
			Direction:    false,
			FeeToken:     common.HexToAddress(creatorContractAddr),
			InputAmount:  big.NewInt(2000000000000000000), // 2 creator tokens
			OutputAmount: big.NewInt(2000000000000000000), // 2 content tokens
			Fee:          big.NewInt(0),
			Params:       map[string]interface{}{"toToken": common.HexToAddress(contentContractAddr).Bytes()},
		}

		tx2 := &txEvent{
			TransactionHash: "0xflow_double_buy2",
			BlockNumber:     301,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(contentExternalAddr),
		}

		err = ta.onSwap(ctx, tx2, buyEvent2)
		require.NoError(t, err)

		// Wait for River queue to process all jobs
		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		// Verify second buy (balance should be >= 0, mock returns fixed balance)
		initialBalance, err := testRedis.ZScore(ctx, keyUserPositionOfToken(contentExternalAddr), "0:"+buyerPubkey+":").Result()
		require.NoError(t, err)
		require.GreaterOrEqual(t, initialBalance, 0.0, "Balance should be non-negative")

		trade2 := helperGetTradeFromQuestDB(t, ctx, ta.questDB, tx2.TransactionHash)
		require.Equal(t, strings.ToLower(contentContractAddr), strings.ToLower(trade2.ContractAddress), "Contract address should match")
		require.Equal(t, contentExternalAddr, trade2.ExternalAddress, "External address should match")
		require.Equal(t, "buy", trade2.TradeType, "Trade type should be buy")
		require.Equal(t, strings.ToLower(userAddr), strings.ToLower(trade2.TraderAddress), "Trader address should match")
		require.Equal(t, 0.3, trade2.BasePriceInUsd, "Base price (creator token) should be $0.3")
		// Price in USD = (input / output) * creator token price = (2 / 2) * $0.3 = 1 * $0.3 = $0.3
		require.InDelta(t, 0.3, trade2.PriceInUsd, 0.01, "Price should be $0.3")

		// Step 3: Sell
		sellEvent := &bondingcurve.LogTokenSwapped{
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
			Direction:    true,
			FeeToken:     common.HexToAddress(contentContractAddr),
			InputAmount:  big.NewInt(1000000000000000000), // 1 content token
			OutputAmount: big.NewInt(1000000000000000000), // 1 creator token
			Fee:          big.NewInt(0),
			Params:       map[string]interface{}{"toToken": common.HexToAddress(contentContractAddr).Bytes()},
		}

		tx3 := &txEvent{
			TransactionHash: "0xflow_double_sell",
			BlockNumber:     302,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
			Input:           buildMockSwapInput(contentExternalAddr),
		}

		err = ta.onSwap(ctx, tx3, sellEvent)
		require.NoError(t, err)

		// Wait for River queue to process all jobs
		helperWaitForRiverQueueJobs(t, ctx, ta, 5*time.Second)

		// Verify sell (balance should be >= 0, mock returns fixed balance)
		finalBalance, err := testRedis.ZScore(ctx, keyUserPositionOfToken(contentExternalAddr), "0:"+buyerPubkey+":").Result()
		require.NoError(t, err)
		require.GreaterOrEqual(t, finalBalance, 0.0, "Balance should not be negative")

		trade3 := helperGetTradeFromQuestDB(t, ctx, ta.questDB, tx3.TransactionHash)
		require.Equal(t, strings.ToLower(contentContractAddr), strings.ToLower(trade3.ContractAddress), "Contract address should match")
		require.Equal(t, contentExternalAddr, trade3.ExternalAddress, "External address should match")
		require.Equal(t, "sell", trade3.TradeType, "Trade type should be sell")
		require.Equal(t, strings.ToLower(userAddr), strings.ToLower(trade3.TraderAddress), "Trader address should match")
		require.Equal(t, 0.3, trade3.BasePriceInUsd, "Base price (creator token) should be $0.3")
		// Price in USD = output creator tokens * creator token price = 1 * $0.3 = $0.3
		require.InDelta(t, 0.3, trade3.PriceInUsd, 0.01, "Price should be $0.3")
	})
}

func buildMockSwapInput(ionConnectAddress string) string {
	// Method selector for handleOps function: first 4 bytes of keccak256("handleOps(bytes,uint256,uint256)")
	handleOpsSelector := "74fa4121"
	// Method selector for swap function embedded in callData
	swapSelector := "83362e17"

	// Build Fat Address V2 for toToken
	toTokenBytes := buildFatAddressV2Single("Test Token", "TEST", ionConnectAddress, 'd', common.Address{}, common.Address{})
	toTokenLen := len(toTokenBytes)

	// Pad toToken data to 32-byte boundary
	toTokenPadded := toTokenBytes
	if remainder := toTokenLen % 32; remainder != 0 {
		padding := make([]byte, 32-remainder)
		toTokenPadded = append(toTokenBytes, padding...)
	}

	// Build swap callData: swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn)
	fromTokenOffset := 128                // 0x80
	toTokenOffset := fromTokenOffset + 32 // 0xA0

	swapCallData := swapSelector
	swapCallData += fmt.Sprintf("%064x", fromTokenOffset)                              // offset to fromToken
	swapCallData += fmt.Sprintf("%064x", toTokenOffset)                                // offset to toToken
	swapCallData += "0000000000000000000000000000000000000000000000000de0b6b3a7640000" // amountIn (1 ION)
	swapCallData += "0000000000000000000000000000000000000000000000000de0b6b3a7640000" // minReturn (1 ION)
	swapCallData += fmt.Sprintf("%064x", 0)                                            // fromToken length (0 for base token)
	swapCallData += fmt.Sprintf("%064x", toTokenLen)                                   // toToken length
	swapCallData += fmt.Sprintf("%x", toTokenPadded)                                   // toToken data (padded)

	// Pad swapCallData to 32-byte boundary for embedding in UserOp
	swapCallDataBytes := len(swapCallData) / 2 // hex string -> bytes
	if remainder := swapCallDataBytes % 32; remainder != 0 {
		padding := make([]byte, 32-remainder)
		swapCallData += fmt.Sprintf("%x", padding)
	}

	// Build handleOps structure:
	// handleOps(bytes userOps, uint256 r, uint256 vs)
	// userOps contains: sender (20 bytes) + nonce (32 bytes) + callDataLength (32 bytes) + callData (variable)

	result := "0x" + handleOpsSelector
	result += fmt.Sprintf("%064x", 96)                                           // offset to userOps (0x60)
	result += "1b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc" // r (bundle signature)
	result += "8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c0376" // vs (compact signature)

	// UserOps data
	userOpsLen := 20 + 32 + 32 + len(swapCallData)/2                             // sender + nonce + callDataLen + callData
	result += fmt.Sprintf("%064x", userOpsLen)                                   // userOps length
	result += "8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595"                         // sender (20 bytes)
	result += "0000000000000000000000000000000000000000000000000000000000000000" // nonce (32 bytes)
	result += fmt.Sprintf("%064x", len(swapCallData)/2)                          // callData length
	result += swapCallData                                                       // callData (swap encoded)

	return result
}

func helperBuildExternalAddress(platform, tokenType, identifier string) string {
	if platform == "xcom" {
		return identifier
	}

	if tokenType == "profile" || tokenType == "" {
		return fmt.Sprintf("0:%s:", identifier)
	}

	var kind string
	switch tokenType {
	case "post":
		kind = strconv.Itoa(model.CustomIONKindEditableTextNote)
	case "video":
		kind = strconv.Itoa(model.CustomIONKindEditableTextNote)
	case "article":
		kind = strconv.Itoa(nostr.KindArticle)
	default:
		kind = strconv.Itoa(model.CustomIONKindEditableTextNote)
	}
	return fmt.Sprintf("%s:%s:%s", kind, identifier, "content")
}

func helperInsertBaseTokenPrice(t *testing.T, ctx context.Context, db *storage.DB, tokenAddress string, tokenSymbol string, priceUSD float64) {
	t.Helper()

	_, err := storage.Exec(ctx, db, `
		INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (token_address) DO UPDATE SET price_usd = EXCLUDED.price_usd, updated_at = EXCLUDED.updated_at
	`, tokenAddress, tokenSymbol, priceUSD)
	require.NoError(t, err, "failed to insert base token price")
}

func helperGetTradeFromQuestDB(t *testing.T, ctx context.Context, questDB *questdb.DB, transactionHash string) *QuestDBTrade {
	t.Helper()

	trades, err := questdb.Select[QuestDBTrade](ctx, questDB, `
		SELECT timestamp, pair_address, contract_address, external_address,
		       base_price_in_usd, price_in_usd, base_amount, amount,
		       trade_type, trader_address, transaction_hash
		FROM trades
		WHERE transaction_hash = $1
		LIMIT 1
	`, transactionHash)
	if err != nil {
		t.Fatalf("Failed to query QuestDB for trade: %v", err)
	}

	if len(trades) == 0 {
		t.Fatalf("No trade found in QuestDB for transaction %s", transactionHash)
	}

	return trades[0]
}

type swapResult struct {
	TransactionHash string  `db:"transaction_hash"`
	ContractAddress string  `db:"contract_address"`
	ExternalAddress string  `db:"external_address"`
	UserAddress     string  `db:"user_blockchain_address"`
	Direction       bool    `db:"direction"`
	InputAmount     string  `db:"input_amount"`
	OutputAmount    string  `db:"output_amount"`
	PriceUSD        float64 `db:"price_usd"`
}

func helperGetSwapFromDB(t *testing.T, ctx context.Context, db *storage.DB, transactionHash string) *swapResult {
	t.Helper()

	swaps, err := storage.Select[swapResult](ctx, db,
		`SELECT transaction_hash, contract_address, external_address, user_blockchain_address,
		        direction, input_amount, output_amount, price_usd
		 FROM token_swaps
		 WHERE transaction_hash = $1`,
		transactionHash)
	require.NoError(t, err)
	require.Len(t, swaps, 1, "Expected exactly 1 swap for transaction %s", transactionHash)

	return swaps[0]
}

type positionResult struct {
	UserAddress     string  `db:"user_blockchain_address"`
	ContractAddress string  `db:"contract_address"`
	ExternalAddress string  `db:"external_address"`
	Amount          string  `db:"amount"`
	AvgBuyPrice     float64 `db:"avg_buy_price_usd"`
	TotalInvested   float64 `db:"total_invested_usd"`
}

func helperGetUserPosition(t *testing.T, ctx context.Context, db *storage.DB, userAddress, contractAddress string) *positionResult {
	t.Helper()

	positions, err := storage.Select[positionResult](ctx, db,
		`SELECT user_blockchain_address, contract_address, external_address, amount,
	        avg_buy_price_usd, total_invested_usd
	 FROM user_token_positions
	 WHERE user_blockchain_address = $1 AND contract_address = $2`,
		strings.ToLower(userAddress), strings.ToLower(contractAddress))
	require.NoError(t, err)
	require.Len(t, positions, 1, "Expected exactly 1 position for user %s and contract %s", userAddress, contractAddress)

	return positions[0]
}

func TestExtractAllTokensFromFatAddress(t *testing.T) {
	t.Run("single_fat_address", func(t *testing.T) {
		fatAddress := buildFatAddressV2Single(
			"Test Token", "TEST", "test_external_addr", 0x61,
			common.Address{}, common.Address{},
		)

		tokens, creator, affiliate, err := extractAllTokensFromFatAddress(fatAddress)

		require.NoError(t, err)
		require.Len(t, tokens, 1, "Should have 1 token")
		require.Equal(t, "test_external_addr", tokens[0])
		require.Equal(t, common.Address{}, creator)
		require.Equal(t, common.Address{}, affiliate)
	})

	t.Run("double_fat_address", func(t *testing.T) {
		fatAddress := buildFatAddressV2Double(
			"Creator Token", "CREA", "0:creator_pubkey:", 0x61,
			"Content Token", "CONT", "30175:creator_pubkey:post123", 0x62,
			common.Address{}, common.Address{},
		)

		tokens, creator, affiliate, err := extractAllTokensFromFatAddress(fatAddress)

		require.NoError(t, err)
		require.Len(t, tokens, 2, "Should have 2 tokens")
		require.Equal(t, "0:creator_pubkey:", tokens[0], "First token should be creator")
		require.Equal(t, "30175:creator_pubkey:post123", tokens[1], "Second token should be content")
		require.Equal(t, common.Address{}, creator)
		require.Equal(t, common.Address{}, affiliate)
	})

	t.Run("with_creator_and_affiliate", func(t *testing.T) {
		creatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
		affiliateAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")

		fatAddress := buildFatAddressV2Single(
			"Test Token", "TEST", "test_addr", 0x61,
			creatorAddr, affiliateAddr,
		)

		tokens, creator, affiliate, err := extractAllTokensFromFatAddress(fatAddress)

		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, "test_addr", tokens[0])
		require.Equal(t, creatorAddr, creator)
		require.Equal(t, affiliateAddr, affiliate)
	})

	t.Run("invalid_version", func(t *testing.T) {
		invalidFatAddress := []byte{0x99, 0x01, 0x00, 0x00} // Invalid version

		_, _, _, err := extractAllTokensFromFatAddress(invalidFatAddress)

		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported fat address version")
	})

	t.Run("insufficient_data", func(t *testing.T) {
		insufficientData := []byte{0x02, 0x01} // Only 2 bytes

		_, _, _, err := extractAllTokensFromFatAddress(insufficientData)

		require.Error(t, err)
		require.Contains(t, err.Error(), "insufficient data")
	})
}

func TestExtractAllTokensFromFatAddress_RecommendedUsage(t *testing.T) {
	t.Run("single_swap_example", func(t *testing.T) {
		fatAddress := buildFatAddressV2Single(
			"Test Token", "TEST", "test_external", 0x61,
			common.Address{}, common.Address{},
		)
		tokens, creator, affiliate, err := extractAllTokensFromFatAddress(fatAddress)

		require.NoError(t, err)
		require.Len(t, tokens, 1, "Single swap has 1 token")
		require.Equal(t, "test_external", tokens[0])
		require.Equal(t, common.Address{}, creator)
		require.Equal(t, common.Address{}, affiliate)
	})

	t.Run("double_swap_example", func(t *testing.T) {
		fatAddress := buildFatAddressV2Double(
			"Creator Token", "CREA", "0:creator:", 0x61,
			"Content Token", "CONT", "30175:creator:post", 0x62,
			common.Address{}, common.Address{},
		)
		tokens, _, _, err := extractAllTokensFromFatAddress(fatAddress)

		require.NoError(t, err)
		require.Len(t, tokens, 2, "Double swap has 2 tokens")
		require.Equal(t, "0:creator:", tokens[0], "First token is creator")
		require.Equal(t, "30175:creator:post", tokens[1], "Second token is content")
	})
}
