// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	wintrtime "github.com/ice-blockchain/wintr/time"
)

const bondingCurveAddr = "0x8d86c992ce7812a64101da9b2531d5f378d682e2"

func TestOnSwap(t *testing.T) {
	t.Skip()
	// Note: Not using t.Parallel() because QuestDB pool is shared across subtests

	ionPrice := 0.1 // $0.1 per ION
	ta := &tokenAnalytics{
		ingestedDataDB:  testDB,
		processedDataDB: testRedis,
		// questDB:                     testQuestDB,
		bondingCurveContractAddress: bondingCurveAddr,
		cfg: &config{
			IONTokenAddress: "0xfffe00ab26d8d121a51717306adbebc70b8b7247",
		},
		ionPriceUSD: &atomic.Pointer[float64]{},
	}
	ta.ionPriceUSD.Store(&ionPrice)

	t.Run("processes_buy_swap_successfully", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		contractAddress := "0x4be0f647afd324dfe58b3af90d0e91cc3ff89f67"
		ionConnectAddr := "30023:testpubkey123:article1"
		masterPubkey := "testpubkey123"
		userAddr := "0x41e0385d6c933a11a705b93b04a728ad80c3a67c"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247"

		helperInsertTestUser(t, ctx, testDB, masterPubkey, "testuser", "Test User", userAddr, false)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10) // 1000 tokens

		tokenCreatedEvent := &bondingcurve.LogTokenCreated{
			Address:           common.HexToAddress(contractAddress),
			Name:              "Test Token",
			Symbol:            "TEST",
			IonConnectAddress: ionConnectAddr,
			TotalSupply:       totalSupply,
		}

		tx1 := &txEvent{
			TransactionHash: "0xtest_create_token_buy",
			BlockNumber:     1,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
		}

		err := ta.onTokenCreated(ctx, tx1, bondingCurveAddr, tokenCreatedEvent)
		require.NoError(t, err)

		pairRegisteredEvent := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0x36d6846c1bbd47fd80454415bef17cd169a55733231bd03afa004b03255b81b0"),
			BaseToken:  common.HexToAddress(baseToken),
			OtherToken: common.HexToAddress(contractAddress),
		}

		err = ta.onPairRegistered(ctx, tx1, pairRegisteredEvent)
		require.NoError(t, err)

		swapTotalSupply := new(big.Int)
		swapTotalSupply.SetString("1000000000000000000000", 10)

		swapEvent := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress(contractAddress),
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x36d6846c1bbd47fd80454415bef17cd169a55733231bd03afa004b03255b81b0"),
			Direction:    false, // false = buy (user sends base token, gets community token)
			TotalSupply:  swapTotalSupply,
			InputAmount:  big.NewInt(1000000000000000000), // 1 ION input
			OutputAmount: big.NewInt(1000000000000000000), // 1 token output
			Fee:          big.NewInt(0),
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

		type swapResult struct {
			TransactionHash   string  `db:"transaction_hash"`
			ContractAddress   string  `db:"contract_address"`
			IonConnectAddress string  `db:"ion_connect_address"`
			UserAddress       string  `db:"user_address"`
			Direction         bool    `db:"direction"`
			InputAmount       string  `db:"input_amount"`
			OutputAmount      string  `db:"output_amount"`
			PriceUSD          float64 `db:"price_usd"`
		}

		swaps, err := storage.Select[swapResult](ctx, testDB,
			`SELECT transaction_hash, contract_address, ion_connect_address, user_address, 
			        direction, input_amount, output_amount, price_usd 
			 FROM token_swaps 
			 WHERE transaction_hash = $1`,
			tx2.TransactionHash)
		require.NoError(t, err)
		require.Len(t, swaps, 1)

		swap := swaps[0]
		assert.Equal(t, tx2.TransactionHash, swap.TransactionHash)
		assert.Equal(t, strings.ToLower(contractAddress), swap.ContractAddress)
		assert.Equal(t, ionConnectAddr, swap.IonConnectAddress)
		assert.Equal(t, strings.ToLower(userAddr), swap.UserAddress)
		assert.Equal(t, false, swap.Direction) // buy
		assert.Equal(t, "1000000000000000000", swap.InputAmount)
		assert.Equal(t, "1000000000000000000", swap.OutputAmount)
		assert.Equal(t, 0.1, swap.PriceUSD) // 1 ION * $0.1 = $0.1

		type positionResult struct {
			MasterPubkey      string  `db:"master_pubkey"`
			ContractAddress   string  `db:"contract_address"`
			IonConnectAddress string  `db:"ion_connect_address"`
			Amount            string  `db:"amount"`
			AvgBuyPriceUSD    float64 `db:"avg_buy_price_usd"`
			TotalInvestedUSD  float64 `db:"total_invested_usd"`
		}

		positions, err := storage.Select[positionResult](ctx, testDB,
			`SELECT master_pubkey, contract_address, ion_connect_address, amount, 
			        avg_buy_price_usd, total_invested_usd 
			 FROM user_token_positions 
			 WHERE master_pubkey = $1 AND contract_address = $2`,
			masterPubkey, contractAddress)
		require.NoError(t, err)
		require.Len(t, positions, 1)

		position := positions[0]
		assert.Equal(t, masterPubkey, position.MasterPubkey)
		assert.Equal(t, strings.ToLower(contractAddress), position.ContractAddress)
		assert.Equal(t, ionConnectAddr, position.IonConnectAddress)
		assert.Equal(t, "1000000000000000000", position.Amount) // 1 token
		assert.Equal(t, 0.1, position.AvgBuyPriceUSD)           // $0.1
		assert.Equal(t, 0.1, position.TotalInvestedUSD)         // 1 ION * $0.1 = $0.1

		redisKey := keyUserPositionOfToken(ionConnectAddr)
		userIonConnect := "0:" + masterPubkey + ":" // kind=0 for user profile
		score, err := testRedis.ZScore(ctx, redisKey, userIonConnect).Result()
		require.NoError(t, err)
		assert.Equal(t, float64(1), score) // 1 token (stored as count, not USD)
	})

	t.Run("processes_sell_swap_successfully", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		contractAddress := "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8"
		ionConnectAddr := "30023:sellerpubkey456:post2"
		masterPubkey := "sellerpubkey456"
		userAddr := "0xc6646173c7f997949494dfd87d2076ea41b801fb"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247" // Use same ION token

		helperInsertTestUser(t, ctx, testDB, masterPubkey, "selleruser", "Seller User", userAddr, false)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10)

		tokenCreatedEvent := &bondingcurve.LogTokenCreated{
			Address:           common.HexToAddress(contractAddress),
			Name:              "Sell Token",
			Symbol:            "SELL",
			IonConnectAddress: ionConnectAddr,
			TotalSupply:       totalSupply,
		}

		tx1 := &txEvent{
			TransactionHash: "0xtest_create_token_sell",
			BlockNumber:     10,
			FromAddress:     userAddr,
			BlockTimestamp:  now,
		}

		err := ta.onTokenCreated(ctx, tx1, bondingCurveAddr, tokenCreatedEvent)
		require.NoError(t, err)

		pairRegisteredEvent := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"),
			BaseToken:  common.HexToAddress(baseToken),
			OtherToken: common.HexToAddress(contractAddress),
		}

		err = ta.onPairRegistered(ctx, tx1, pairRegisteredEvent)
		require.NoError(t, err)

		buyTotalSupply := new(big.Int)
		buyTotalSupply.SetString("1000000000000000000000", 10)

		buyEvent := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress(contractAddress),
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"),
			Direction:    false, // buy
			TotalSupply:  buyTotalSupply,
			InputAmount:  big.NewInt(2000000000000000000), // 2 ION
			OutputAmount: big.NewInt(2000000000000000000), // 2 tokens
			Fee:          big.NewInt(0),
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

		sellTotalSupply := new(big.Int)
		sellTotalSupply.SetString("1000000000000000000000", 10)

		sellEvent := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress(contractAddress),
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"),
			Direction:    true, // true = sell (user sends community token, gets base token)
			TotalSupply:  sellTotalSupply,
			InputAmount:  big.NewInt(1000000000000000000), // 1 token input
			OutputAmount: big.NewInt(1000000000000000000), // 1 ION output
			Fee:          big.NewInt(0),
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

		type swapResult struct {
			Direction    bool    `db:"direction"`
			InputAmount  string  `db:"input_amount"`
			OutputAmount string  `db:"output_amount"`
			PriceUSD     float64 `db:"price_usd"`
		}

		swaps, err := storage.Select[swapResult](ctx, testDB,
			`SELECT direction, input_amount, output_amount, price_usd 
			 FROM token_swaps 
			 WHERE transaction_hash = $1`,
			tx3.TransactionHash)
		require.NoError(t, err)
		require.Len(t, swaps, 1)

		swap := swaps[0]
		assert.Equal(t, true, swap.Direction) // sell
		assert.Equal(t, "1000000000000000000", swap.InputAmount)
		assert.Equal(t, "1000000000000000000", swap.OutputAmount)
		assert.Equal(t, 0.1, swap.PriceUSD) // 1 ION * $0.1 = $0.1

		type positionResult struct {
			Amount           string  `db:"amount"`
			AvgBuyPriceUSD   float64 `db:"avg_buy_price_usd"`
			TotalInvestedUSD float64 `db:"total_invested_usd"`
		}

		positions, err := storage.Select[positionResult](ctx, testDB,
			`SELECT amount, avg_buy_price_usd, total_invested_usd 
			 FROM user_token_positions 
			 WHERE master_pubkey = $1 AND contract_address = $2`,
			masterPubkey, contractAddress)
		require.NoError(t, err)
		require.Len(t, positions, 1)

		position := positions[0]
		assert.Equal(t, "1000000000000000000", position.Amount) // 2 - 1 = 1 token left
		// After buying 2 tokens at price $0.1 (total invested $0.2), avg buy price = $0.1
		assert.InDelta(t, 0.1, position.AvgBuyPriceUSD, 0.001)
		assert.InDelta(t, 0.2, position.TotalInvestedUSD, 0.001) // 2 ION * $0.1

		redisKey := keyUserPositionOfToken(ionConnectAddr)
		userIonConnect := "0:" + masterPubkey + ":" // kind=0 for user profile
		score, err := testRedis.ZScore(ctx, redisKey, userIonConnect).Result()
		require.NoError(t, err)
		assert.Equal(t, float64(1), score) // 1 token remaining
	})

	t.Run("updates_market_cap_correctly", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		contractAddress := "0xabc123def456789012345678901234567890abcd"
		ionConnectAddr := "30023:marketpubkey:video1"
		masterPubkey := "marketpubkey"
		userAddr := "0x1234567890123456789012345678901234567890"
		baseToken := "0xfffe00ab26d8d121a51717306adbebc70b8b7247"

		helperInsertTestUser(t, ctx, testDB, masterPubkey, "marketuser", "Market User", userAddr, false)

		helperInsertTestToken(t, ctx, testDB,
			contractAddress,
			ionConnectAddr,
			"MKT",
			TokenTypeVideo,
			masterPubkey,
			"1000000000000000000000",
			50.0, // initial market cap $50
			0.05, // initial price $0.05
			0)

		_, err := storage.Exec(ctx, testDB, `
			UPDATE tokens SET base_token = $1 WHERE contract_address = $2
		`, baseToken, contractAddress)
		require.NoError(t, err)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10)

		event := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress(contractAddress),
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0xaaabbbcccdddeeefffaaabbbcccdddeeefffaaabbbcccdddeeefffaaabbbcccd"),
			Direction:    false, // buy
			TotalSupply:  totalSupply,
			InputAmount:  big.NewInt(5000000000000000000), // 5 ION
			OutputAmount: big.NewInt(5000000000000000000), // 5 tokens
			Fee:          big.NewInt(0),
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

		type tokenCheck struct {
			MarketCapUSD float64 `db:"market_cap_usd"`
			PriceUSD     float64 `db:"price_usd"`
		}
		tokenData, err := storage.Select[tokenCheck](ctx, testDB,
			`SELECT market_cap_usd, price_usd FROM tokens WHERE ion_connect_address = $1`,
			ionConnectAddr)
		require.NoError(t, err)
		require.Len(t, tokenData, 1)

		// Delta = sign * tokenAmount * priceUSD
		// sign = +1 (buy), tokenAmount = 5, priceUSD = 5 ION * $0.1 = $0.5
		// Delta = +1 * 5 * 0.1 = +0.5
		// Initial market cap from token creation should be close to 0, then increased by 0.5
		assert.True(t, tokenData[0].MarketCapUSD > 0, "Market cap should be positive")

		// Verify price updated
		// Price per token = inputAmount / outputAmount * ION price
		// = 5 ION / 5 tokens * $0.1 = 1 * $0.1 = $0.1
		assert.Equal(t, 0.1, tokenData[0].PriceUSD)
	})

	t.Run("rejects_swap_with_invalid_base_token", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		// Test data
		contractAddress := "0xbadtoken1234567890123456789012345678abcd"
		ionConnectAddr := "30023:badpubkey:article2"
		masterPubkey := "badpubkey"
		userAddr := "0x9999999999999999999999999999999999999999"

		helperInsertTestUser(t, ctx, testDB, masterPubkey, "baduser", "Bad User", userAddr, false)
		helperInsertTestToken(t, ctx, testDB,
			contractAddress,
			ionConnectAddr,
			"BAD",
			TokenTypeArticle,
			masterPubkey,
			"1000000000000000000000",
			10.0,
			0.01,
			0)

		now := wintrtime.Now()
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000", 10)

		event := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress(contractAddress),
			Swapper:      common.HexToAddress(userAddr),
			Pair:         common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
			Direction:    false,
			TotalSupply:  totalSupply,
			InputAmount:  big.NewInt(1000000000000000000),
			OutputAmount: big.NewInt(1000000000000000000),
			Fee:          big.NewInt(0),
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
		assert.Contains(t, err.Error(), "not found")
	})
}

func buildMockSwapInput(ionConnectAddress string) string {
	// Method selector for swap function: first 4 bytes of keccak256("swap(bytes,bytes,uint256,uint256)")
	methodSelector := "83362e17"

	// ABI encode: swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn)
	// Structure:
	// [0:32]   - offset to fromToken
	// [32:64]  - offset to toToken
	// [64:96]  - amountIn
	// [96:128] - minReturn
	// [128:160] - fromToken length
	// [160:...] - fromToken data (empty for base token)
	// [...:...] - toToken length
	// [...:...] - toToken data

	toTokenBytes := []byte(ionConnectAddress)
	toTokenLen := len(toTokenBytes)

	// Pad toToken data to 32-byte boundary
	toTokenPadded := toTokenBytes
	if remainder := toTokenLen % 32; remainder != 0 {
		padding := make([]byte, 32-remainder)
		toTokenPadded = append(toTokenBytes, padding...)
	}

	// Calculate offsets (in bytes from start of input data, after method selector)
	fromTokenOffset := 128 // 0x80 - points to fromToken length field
	// fromToken: length (32 bytes) + data (0 bytes) = 32 bytes total
	toTokenOffset := fromTokenOffset + 32 // 0xA0 - points to toToken length field

	// Build the encoded data
	result := "0x" + methodSelector
	result += fmt.Sprintf("%064x", fromTokenOffset)                              // [0:32] offset to fromToken
	result += fmt.Sprintf("%064x", toTokenOffset)                                // [32:64] offset to toToken
	result += "0000000000000000000000000000000000000000000000000de0b6b3a7640000" // [64:96] amountIn (1 ION)
	result += "0000000000000000000000000000000000000000000000000de0b6b3a7640000" // [96:128] minReturn (1 ION)
	result += fmt.Sprintf("%064x", 0)                                            // [128:160] fromToken length (0 for base token)
	result += fmt.Sprintf("%064x", toTokenLen)                                   // [160:192] toToken length
	result += fmt.Sprintf("%x", toTokenPadded)                                   // [192:...] toToken data (padded)

	return result
}
