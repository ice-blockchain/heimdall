//go:build test

// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestTokenSwapped(t *testing.T) {
	t.Run("first_swap_with_v2_fat_address", func(t *testing.T) {
		// Global Header: [version=2][recordsCount=1][presenceMask=0x0003 (both creator & affiliate)]
		// Token Header: [nameLen][symbolLen][extAddrLen][extType][tokenMask=0x00000000]
		// Bonding Address: 20 bytes (mandatory, zeroed)
		// Strings: name, symbol, externalAddress
		// Global Addresses: creator(20), affiliate(20)
		name := "Test Token"
		symbol := "TEST"
		extAddr := "0:pubkey:test"
		creatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
		affiliateAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")

		fatAddr := []byte{
			0x02,       // version
			0x01,       // recordsCount
			0x00, 0x03, // presenceMask (creator | affiliate)
			// Token header
			byte(len(name)), byte(len(symbol)), byte(len(extAddr)), 0x61, // [nameLen][symbolLen][extAddrLen][extType=Ion Profile]
			0x00, 0x00, 0x00, 0x00, // tokenMask (no bonding params)
		}
		// Bonding address (20 bytes, zeroed)
		fatAddr = append(fatAddr, make([]byte, 20)...)
		// Strings
		fatAddr = append(fatAddr, []byte(name)...)
		fatAddr = append(fatAddr, []byte(symbol)...)
		fatAddr = append(fatAddr, []byte(extAddr)...)
		// Global addresses
		fatAddr = append(fatAddr, creatorAddr.Bytes()...)
		fatAddr = append(fatAddr, affiliateAddr.Bytes()...)

		// Encode tx input for swap(bytes fromToken, bytes toToken, uint256 amountIn, uint256 minReturn)
		fromToken := common.HexToAddress("0x2c73996babf1a06c2c057177353293f7ca0907c8").Bytes()
		amountIn := big.NewInt(1000000000000000000) // 1 token
		minReturn := big.NewInt(990000000000000000) // 0.99 token

		txInputData, err := abi4Param.Methods["swap"].Inputs.Pack(fromToken, fatAddr, amountIn, minReturn)
		require.NoError(t, err)
		txInput := "0x" + hex.EncodeToString(append(abi4Param.Methods["swap"].ID, txInputData...))

		// Event data for Swapped (includes feeToken field)
		// event Swapped(address indexed swapper, bytes32 indexed pairId, bool direction, address feeToken, uint256 inputAmount, uint256 outputAmount, uint256 fee)
		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false (buy)
			"0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8" + // feeToken (NEW FIELD)
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" + // inputAmount = 1 token
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" + // outputAmount = 1 token
			"0000000000000000000000000000000000000000000000000000000000000000" // fee = 0

		event, err := tokenSwapped(
			eventSwapped.Hex(),
			eventData,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",                         // contract
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c", // swapper
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2", // pairId
			txInput,
		)

		require.NoError(t, err, "Should parse V2 first swap without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)
		require.Contains(t, event.Params, "fromToken")
		require.Contains(t, event.Params, "toToken")
		require.Contains(t, event.Params, "amountIn")
		require.Contains(t, event.Params, "minReturn")

		toToken, ok := event.Params["toToken"].([]byte)
		require.True(t, ok, "toToken should be []byte")
		require.Greater(t, len(toToken), 32, "V2 fat address should be > 32 bytes")
		require.Equal(t, byte(0x02), toToken[0], "Should be version 2")
	})

	t.Run("subsequent_swap_with_thin_address", func(t *testing.T) {
		fromToken := common.HexToAddress("0x2c73996babf1a06c2c057177353293f7ca0907c8").Bytes()
		toToken := common.HexToAddress("0x0f93afe4f21f8885b99932214c66be3ff42e2162").Bytes()
		amountIn := big.NewInt(500000000000000000) // 0.5 token
		minReturn := big.NewInt(495000000000000000)

		txInputData, err := abi4Param.Methods["swap"].Inputs.Pack(fromToken, toToken, amountIn, minReturn)
		require.NoError(t, err)
		txInput := "0x" + hex.EncodeToString(append(abi4Param.Methods["swap"].ID, txInputData...))

		// Event data (includes feeToken)
		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false
			"0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8" + // feeToken
			"0000000000000000000000000000000000000000000000000006f05b59d3b20000" + // inputAmount
			"0000000000000000000000000000000000000000000000000006f05b59d3b20000" + // outputAmount
			"0000000000000000000000000000000000000000000000000000000000000000" // fee

		event, err := tokenSwapped(
			eventSwapped.Hex(),
			eventData,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c",
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2",
			txInput,
		)

		require.NoError(t, err, "Should parse subsequent swap without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)
		require.Contains(t, event.Params, "fromToken")
		require.Contains(t, event.Params, "toToken")

		toTokenBytes, ok := event.Params["toToken"].([]byte)
		require.True(t, ok, "toToken should be []byte")
		require.Equal(t, 20, len(toTokenBytes), "Subsequent swap should have thin address (20 bytes)")
	})

	t.Run("swap_with_permit_5param", func(t *testing.T) {
		fromToken := common.HexToAddress("0xfffe00ab26d8d121a51717306adbebc70b8b7247").Bytes()
		toToken := common.HexToAddress("0x25c4b7a88c2d4be2558cf3ba68d42e0b46cbe388").Bytes()
		amountIn, _ := new(big.Int).SetString("100000000000000000000", 10) // 100 tokens
		minReturn, _ := new(big.Int).SetString("99000000000000000000", 10)
		permitValue, _ := new(big.Int).SetString("100000000000000000000", 10)
		permitData := struct {
			Value    *big.Int
			Deadline *big.Int
			V        uint8
			R        [32]byte
			S        [32]byte
		}{
			Value:    permitValue,
			Deadline: big.NewInt(1705034976),
			V:        27,
			R:        [32]byte{0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21},
			S:        [32]byte{0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef},
		}

		txInputData, err := ABI.Methods["swap"].Inputs.Pack(fromToken, toToken, amountIn, minReturn, permitData)
		require.NoError(t, err)
		txInput := "0x" + hex.EncodeToString(append(ABI.Methods["swap"].ID, txInputData...))

		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false
			"000000000000000000000000fffe00ab26d8d121a51717306adbebc70b8b7247" + // feeToken
			"0000000000000000000000000000000000000000000000056bc75e2d63100000" + // inputAmount
			"0000000000000000000000000000000000000000000000056bc75e2d63100000" + // outputAmount
			"0000000000000000000000000000000000000000000000000000000000000000" // fee

		event, err := tokenSwapped(
			eventSwapped.Hex(),
			eventData,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x0000000000000000000000005a4cab6a30022c31534c2ada02c6ac1539d01944",
			"0x0ea54805a12e72704b43361c6fb763c75ecf380a696f294b903a6909ef918530",
			txInput,
		)

		require.NoError(t, err, "Should parse 5-param swap with permit without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)
		require.Contains(t, event.Params, "fromToken")
		require.Contains(t, event.Params, "toToken")
		require.Contains(t, event.Params, "amountIn")
		require.Contains(t, event.Params, "minReturn")
		permit, ok := event.Params["permit"]
		require.True(t, ok, "permit MUST be present in 5-param swap")
		require.NotNil(t, permit, "permit MUST NOT be nil")
	})

	t.Run("double_swap_with_v2_fat_address", func(t *testing.T) {
		// V2 Fat Address with 2 token records (double swap scenario)
		// Global Header: [version=2][recordsCount=2][presenceMask=0x0003]
		creatorName := "Creator Token"
		creatorSymbol := "CREA"
		creatorExtAddr := "0:pubkey:creator123"
		contentName := "Content Token"
		contentSymbol := "CONT"
		contentExtAddr := "30175:postid:456"
		creatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
		affiliateAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")

		fatAddr := []byte{
			0x02,       // version
			0x02,       // recordsCount = 2 (double swap!)
			0x00, 0x03, // presenceMask (creator | affiliate)
			// Token 1 header (creator token)
			byte(len(creatorName)), byte(len(creatorSymbol)), byte(len(creatorExtAddr)), 0x61, // [nameLen][symbolLen][extAddrLen][extType]
			0x00, 0x00, 0x00, 0x00, // tokenMask (no bonding params)
		}
		fatAddr = append(fatAddr, make([]byte, 20)...) // bonding address
		fatAddr = append(fatAddr, []byte(creatorName)...)
		fatAddr = append(fatAddr, []byte(creatorSymbol)...)
		fatAddr = append(fatAddr, []byte(creatorExtAddr)...)

		// Token 2 header (content token)
		fatAddr = append(fatAddr, byte(len(contentName)), byte(len(contentSymbol)), byte(len(contentExtAddr)), 0x62) // extType for post
		fatAddr = append(fatAddr, 0x00, 0x00, 0x00, 0x00)                                                            // tokenMask
		fatAddr = append(fatAddr, make([]byte, 20)...)                                                               // bonding address
		fatAddr = append(fatAddr, []byte(contentName)...)
		fatAddr = append(fatAddr, []byte(contentSymbol)...)
		fatAddr = append(fatAddr, []byte(contentExtAddr)...)

		// Global addresses
		fatAddr = append(fatAddr, creatorAddr.Bytes()...)
		fatAddr = append(fatAddr, affiliateAddr.Bytes()...)

		fromToken := common.HexToAddress("0x2c73996babf1a06c2c057177353293f7ca0907c8").Bytes()
		amountIn := big.NewInt(2000000000000000000)
		minReturn := big.NewInt(1980000000000000000)

		txInputData, err := abi4Param.Methods["swap"].Inputs.Pack(fromToken, fatAddr, amountIn, minReturn)
		require.NoError(t, err)
		txInput := "0x" + hex.EncodeToString(append(abi4Param.Methods["swap"].ID, txInputData...))

		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false (buy)
			"0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8" + // feeToken
			"0000000000000000000000000000000000000000000000001bc16d674ec80000" + // inputAmount = 2 tokens
			"0000000000000000000000000000000000000000000000001b7969ee9b868000" + // outputAmount
			"0000000000000000000000000000000000000000000000000000000000000000" // fee

		event, err := tokenSwapped(
			eventSwapped.Hex(),
			eventData,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c",
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2",
			txInput,
		)

		require.NoError(t, err, "Should parse V2 double swap without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)

		toToken, ok := event.Params["toToken"].([]byte)
		require.True(t, ok, "toToken should be []byte")
		require.Greater(t, len(toToken), 32, "V2 fat address should be > 32 bytes")
		require.Equal(t, byte(0x02), toToken[0], "Should be version 2")
		require.Equal(t, byte(0x02), toToken[1], "Should have 2 token records")
	})

	t.Run("sell_swap", func(t *testing.T) {
		fromToken := common.HexToAddress("0x0f93afe4f21f8885b99932214c66be3ff42e2162").Bytes()
		toToken := common.HexToAddress("0x2c73996babf1a06c2c057177353293f7ca0907c8").Bytes()
		amountIn := big.NewInt(1000000000000000000)
		minReturn := big.NewInt(990000000000000000)

		txInputData, err := abi4Param.Methods["swap"].Inputs.Pack(fromToken, toToken, amountIn, minReturn)
		require.NoError(t, err)
		txInput := "0x" + hex.EncodeToString(append(abi4Param.Methods["swap"].ID, txInputData...))

		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000001" + // direction = true (SELL)
			"0000000000000000000000000f93afe4f21f8885b99932214c66be3ff42e2162" + // feeToken (creator token)
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" + // inputAmount
			"0000000000000000000000000000000000000000000000000dbd2fc137a30000" + // outputAmount
			"000000000000000000000000000000000000000000000000002386f26fc10000" // fee

		event, err := tokenSwapped(
			eventSwapped.Hex(),
			eventData,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c",
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2",
			txInput,
		)

		require.NoError(t, err, "Should parse sell swap without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)

		toTokenBytes, ok := event.Params["toToken"].([]byte)
		require.True(t, ok)
		require.Equal(t, 20, len(toTokenBytes), "Should be thin address")
	})

	t.Run("v2_fat_address_with_bonding_params", func(t *testing.T) {
		// tokenMask = 0x00000006 (bits 1 & 2 set = prices + totalSupply)
		name := "Premium Token"
		symbol := "PREM"
		extAddr := "0:pubkey:premium"
		creatorAddr := common.HexToAddress("0x3333333333333333333333333333333333333333")
		affiliateAddr := common.HexToAddress("0x4444444444444444444444444444444444444444")

		fatAddr := []byte{
			0x02,       // version
			0x01,       // recordsCount
			0x00, 0x03, // presenceMask
			// Token header with bonding params
			byte(len(name)), byte(len(symbol)), byte(len(extAddr)), 0x61,
			0x00, 0x00, 0x00, 0x06, // tokenMask = 0x06 (prices + totalSupply)
		}
		fatAddr = append(fatAddr, make([]byte, 20)...)      // bonding address
		fatAddr = append(fatAddr, make([]byte, 64)...)      // minPrice + maxPrice (2x32 bytes)
		fatAddr = append(fatAddr, make([]byte, 32)...)      // bondingTotalSupply (32 bytes)
		fatAddr = append(fatAddr, []byte(name)...)          // name
		fatAddr = append(fatAddr, []byte(symbol)...)        // symbol
		fatAddr = append(fatAddr, []byte(extAddr)...)       // externalAddress
		fatAddr = append(fatAddr, creatorAddr.Bytes()...)   // creator
		fatAddr = append(fatAddr, affiliateAddr.Bytes()...) // affiliate

		fromToken := common.HexToAddress("0x2c73996babf1a06c2c057177353293f7ca0907c8").Bytes()
		amountIn := big.NewInt(5000000000000000000)
		minReturn := big.NewInt(4950000000000000000)

		txInputData, err := abi4Param.Methods["swap"].Inputs.Pack(fromToken, fatAddr, amountIn, minReturn)
		require.NoError(t, err)
		txInput := "0x" + hex.EncodeToString(append(abi4Param.Methods["swap"].ID, txInputData...))

		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8" +
			"0000000000000000000000000000000000000000000000004563918244f40000" +
			"0000000000000000000000000000000000000000000000004563918244f40000" +
			"0000000000000000000000000000000000000000000000000000000000000000"

		event, err := tokenSwapped(
			eventSwapped.Hex(),
			eventData,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c",
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2",
			txInput,
		)

		require.NoError(t, err, "Should parse V2 with bonding params without error")
		require.NotNil(t, event)
		toToken, ok := event.Params["toToken"].([]byte)
		require.True(t, ok)
		require.Greater(t, len(toToken), 100, "Fat address with bonding params should be larger")
		require.Equal(t, byte(0x02), toToken[0], "Should be version 2")
	})
}

func TestTokenCreated(t *testing.T) {
	t.Run("valid_token_created", func(t *testing.T) {
		// BondingTokenCreated event
		// Field order: name, symbol, externalType, externalAddress, totalSupply, creatorAddress, affiliateAddress
		name := "Test Token"
		symbol := "TEST"
		extType := uint8(0x61) // Ion Profile
		extAddr := "0:pubkey:test123"
		totalSupply, _ := new(big.Int).SetString("1000000000000000000000", 10) // 1000 tokens
		creatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
		affiliateAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")

		nameOffset := uint64(0xe0)    // 7*32 = 224 bytes
		symbolOffset := uint64(0x120) // name offset + 32 (len) + 32 (padded name)
		extAddrOffset := uint64(0x160)

		data := "0x" +
			// name offset
			hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(nameOffset)).Bytes(), 32)) +
			// symbol offset
			hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(symbolOffset)).Bytes(), 32)) +
			// externalType (uint8)
			hex.EncodeToString(common.LeftPadBytes([]byte{extType}, 32)) +
			// externalAddress offset
			hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(extAddrOffset)).Bytes(), 32)) +
			// totalSupply
			hex.EncodeToString(common.LeftPadBytes(totalSupply.Bytes(), 32)) +
			// creatorAddress
			hex.EncodeToString(common.LeftPadBytes(creatorAddr.Bytes(), 32)) +
			// affiliateAddress
			hex.EncodeToString(common.LeftPadBytes(affiliateAddr.Bytes(), 32)) +
			// name length
			hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(len(name))).Bytes(), 32)) +
			// name data (padded to 32)
			hex.EncodeToString(common.RightPadBytes([]byte(name), 32)) +
			// symbol length
			hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(len(symbol))).Bytes(), 32)) +
			// symbol data (padded to 32)
			hex.EncodeToString(common.RightPadBytes([]byte(symbol), 32)) +
			// externalAddress length
			hex.EncodeToString(common.LeftPadBytes(big.NewInt(int64(len(extAddr))).Bytes(), 32)) +
			// externalAddress data (padded to 32)
			hex.EncodeToString(common.RightPadBytes([]byte(extAddr), 32))

		tokenAddr := "0x0f93afe4f21f8885b99932214c66be3ff42e2162"
		event, err := tokenCreated(
			eventTokenCreated.Hex(),
			data,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x"+hex.EncodeToString(common.LeftPadBytes(common.HexToAddress(tokenAddr).Bytes(), 32)),
		)

		require.NoError(t, err, "Should parse TokenCreated event without error")
		require.NotNil(t, event)
		require.Equal(t, strings.ToLower(tokenAddr), strings.ToLower(event.Address.Hex()))
		require.Equal(t, name, event.Name)
		require.Equal(t, symbol, event.Symbol)
		require.NotNil(t, event.TotalSupply)
		require.Equal(t, totalSupply.String(), event.TotalSupply.String())
		require.Equal(t, extType, event.ExternalType)
		require.Equal(t, extAddr, event.ExternalAddress)
		require.Equal(t, strings.ToLower(creatorAddr.Hex()), strings.ToLower(event.CreatorAddress.Hex()))
		require.Equal(t, strings.ToLower(affiliateAddr.Hex()), strings.ToLower(event.AffiliateAddress.Hex()))
	})

	t.Run("invalid_signature", func(t *testing.T) {
		_, err := tokenCreated(
			"0xinvalid",
			"0x0000",
			"0x25c4b7a88c2d4be2558cf3ba68d42e0b46cbe388",
			"0x000000000000000000000000def456789012345678901234567890abcdef456",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("empty_data", func(t *testing.T) {
		_, err := tokenCreated(
			eventTokenCreated.Hex(),
			"",
			"0x25c4b7a88c2d4be2558cf3ba68d42e0b46cbe388",
			"0x000000000000000000000000def456789012345678901234567890abcdef456",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty data")
	})
}

func TestPairRegistered(t *testing.T) {
	t.Run("with_data", func(t *testing.T) {
		pairId := "0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2"
		baseToken := "0x0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8"
		otherToken := "0x0000000000000000000000000f93afe4f21f8885b99932214c66be3ff42e2162"
		priceModel := common.HexToAddress("0xdead000000000000000000000000000000000000")
		startPrice := big.NewInt(1000000000000000000) // 1e18
		endPrice := big.NewInt(2000000000000000000)   // 2e18

		data, err := ABI.Events["PairRegistered"].Inputs.NonIndexed().Pack(
			priceModel,
			startPrice,
			endPrice,
		)
		require.NoError(t, err)

		event, err := pairRegistered(
			eventPairRegistered.Hex(),
			"0x"+hex.EncodeToString(data),
			pairId,
			baseToken,
			otherToken,
		)

		require.NoError(t, err)
		require.NotNil(t, event)
		require.Equal(t, strings.ToLower(pairId), strings.ToLower(event.PairId.Hex()))
		// BaseToken and OtherToken are returned as normal addresses (20 bytes), not as topics (32 bytes with 0x00... prefix)
		require.Equal(t, strings.ToLower("0x2c73996babf1a06c2c057177353293f7ca0907c8"), strings.ToLower(event.BaseToken.Hex()))
		require.Equal(t, strings.ToLower("0x0f93afe4f21f8885b99932214c66be3ff42e2162"), strings.ToLower(event.OtherToken.Hex()))
		require.Equal(t, strings.ToLower(priceModel.Hex()), strings.ToLower(event.PriceModel.Hex()))
		require.Equal(t, startPrice.String(), event.StartPrice.String())
		require.Equal(t, endPrice.String(), event.EndPrice.String())
	})

	t.Run("invalid_signature", func(t *testing.T) {
		_, err := pairRegistered(
			"0xinvalid",
			"0x",
			"0x51ea17cf5c8e1a25a0c9c22ff9208679b60c945cd7057c2607d35a9b110526c0",
			"0x000000000000000000000000fffe00ab26d8d121a51717306adbebc70b8b7247",
			"0x00000000000000000000000025c4b7a88c2d4be2558cf3ba68d42e0b46cbe388",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})
}

func TestFeeAccrued(t *testing.T) {
	t.Run("valid_fee_accrued", func(t *testing.T) {
		data := "0x" +
			"51ea17cf5c8e1a25a0c9c22ff9208679b60c945cd7057c2607d35a9b110526c0" +
			"0000000000000000000000000000000000000000000000056bc75e2d63100000" +
			"0000000000000000000000000000000000000000000000001234567890abcdef" +
			"000000000000000000000000000000000000000000000000fedcba0987654321"

		event, err := feeAccrued(eventFeeAccrued.Hex(), data)

		require.NoError(t, err)
		require.NotNil(t, event)
		require.NotEqual(t, [32]byte{}, event.PairId)
	})
}

func TestUniswapPoolCreated(t *testing.T) {
	t.Run("valid_uniswap_pool_created", func(t *testing.T) {
		data := "0x" +
			"00000000000000000000000000000000000000000000000000000000000000c8" +
			"0000000000000000000000002cc106926e4026d83cbee4d6928dec0e7ec1dc2e"
		token0 := "0x0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8"
		token1 := "0x0000000000000000000000005949a291c17e46cca2f26acf773ba86ee52161b9"
		fee := "0x0000000000000000000000000000000000000000000000000000000000002710"

		event, err := poolCreated(eventPoolCreated.Hex(), data, token0, token1, fee)
		require.NoError(t, err)
		require.Equal(t, event.Token0.Hex(), common.HexToAddress(token0).Hex())
		require.Equal(t, event.Token1.Hex(), common.HexToAddress(token1).Hex())
		require.Equal(t, event.PoolAddress.Hex(), common.HexToAddress("0x2cc106926e4026d83cbee4d6928dec0e7ec1dc2e").Hex())
	})
}

func TestSlippageChecked(t *testing.T) {
	t.Run("valid_slippage_checked", func(t *testing.T) {
		pairId := "0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2"
		data := "0x0000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000de0b6b3a7640000"

		event, err := slippageChecked(eventSlippageChecked.Hex(), data, pairId)

		require.NoError(t, err)
		require.NotNil(t, event)
		require.NotNil(t, event.MinReturn)
		require.NotNil(t, event.ActualOut)
		require.Equal(t, pairId, event.PairId.Hex())
		// minReturn = 0xdbd2fc137a30000 = 987654321000000000
		// actualOut = 0xde0b6b3a7640000 = 1000000000000000000
		require.True(t, event.MinReturn.Cmp(event.ActualOut) < 0, "minReturn should be less than actualOut")
	})

	t.Run("empty_pairId", func(t *testing.T) {
		_, err := slippageChecked(eventSlippageChecked.Hex(), "0x0000", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty pairId")
	})
}

func TestLiquidityLocked(t *testing.T) {
	t.Run("valid_liquidity_locked", func(t *testing.T) {
		pairId := "0x51ea17cf5c8e1a25a0c9c22ff9208679b60c945cd7057c2607d35a9b110526c0"
		data := "0x" +
			"000000000000000000000000abc123def456789012345678901234567890abcd" + // lpToken
			"0000000000000000000000000000000000000000000000056bc75e2d63100000" + // amount
			"0000000000000000000000000000000000000000000000000000000065a0c4e0" // unlockTime

		event, err := liquidityLocked(eventLiquidityLocked.Hex(), data, pairId)

		require.NoError(t, err)
		require.NotNil(t, event)
		require.NotNil(t, event.Amount)
		require.NotNil(t, event.UnlockTime)
		require.NotEqual(t, "0x0000000000000000000000000000000000000000", event.LpToken.Hex())
	})
}

func TestProcessEvent(t *testing.T) {
	t.Run("unknown_event", func(t *testing.T) {
		event, err := ProcessEvent(
			"0xunknown1234567890abcdef1234567890abcdef1234567890abcdef12345678",
			"0x0000",
			[]string{},
			"0x25c4b7a88c2d4be2558cf3ba68d42e0b46cbe388",
			"",
		)

		require.NoError(t, err)
		require.Nil(t, event, "Unknown events should return nil")
	})

	t.Run("insufficient_topics_for_tokenCreated", func(t *testing.T) {
		_, err := ProcessEvent(
			eventTokenCreated.Hex(),
			"0x0000",
			[]string{eventTokenCreated.Hex()}, // Only 1 topic, but needs 2
			"0x25c4b7a88c2d4be2558cf3ba68d42e0b46cbe388",
			"",
		)

		require.Error(t, err)
		require.Contains(t, err.Error(), "requires at least 2 topics")
	})
}

func TestCustomHandleOpsSwapExtraction(t *testing.T) {
	t.Run("verifies_layer1_handleOps_structure", func(t *testing.T) {
		txInput := "0x74fa412100000000000000000000000000000000000000000000000000000000000000601b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c037600000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000"
		hexData := strings.TrimPrefix(txInput, "0x")

		// Check handleOps selector (bytes,uint256,uint256)
		selector := hexData[0:8]
		require.Equal(t, "74fa4121", selector, "Function selector must be handleOps")

		// Check userOps offset (should be 0x60 = 96 bytes)
		userOpsOffsetHex := hexData[8:72]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000060", userOpsOffsetHex, "userOps offset must be 0x60 (96 bytes)")

		// Check r (Bundle transaction signature)
		rHex := hexData[72:136]
		require.Equal(t, "1b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc", rHex, "r signature component must match documentation")

		// Check vs (compact EIP-2098 signature)
		vsHex := hexData[136:200]
		require.Equal(t, "8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c0376", vsHex, "vs signature component must match documentation")

		// Check userOps length (should be 344 bytes = 0x158)
		userOpsLengthHex := hexData[200:264]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000158", userOpsLengthHex, "userOps length must be 0x158 (344 bytes)")

	})

	t.Run("verifies_layer2_userOperation_structure", func(t *testing.T) {
		txInput := "0x74fa412100000000000000000000000000000000000000000000000000000000000000601b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c037600000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000"

		hexData := strings.TrimPrefix(txInput, "0x")
		userOpsDataStart := 264 // userOps data starts at position 264 (after [1.5])

		// Check Sender (Safe wallet address, 20 bytes = 40 hex chars)
		senderHex := hexData[userOpsDataStart : userOpsDataStart+40]
		require.Equal(t, "8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595", senderHex, "Sender must be Safe wallet address from documentation")

		// Check Nonce (32 bytes = 64 hex chars)
		nonceHex := hexData[userOpsDataStart+40 : userOpsDataStart+104]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", nonceHex, "Nonce must be 0 (first transaction)")

		// Check CallData Length (260 bytes = 0x104)
		callDataLengthHex := hexData[userOpsDataStart+104 : userOpsDataStart+168]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000104", callDataLengthHex, "CallData length must be 0x104 (260 bytes)")
	})

	t.Run("verifies_layer3_swap_parameters", func(t *testing.T) {
		txInput := "0x74fa412100000000000000000000000000000000000000000000000000000000000000601b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c037600000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000"

		hexData := strings.TrimPrefix(txInput, "0x")
		callDataStart := 432 // CallData starts at position 432 (264 + 168)

		// Check swap selector (bytes,bytes,uint256,uint256)
		swapSelector := hexData[callDataStart : callDataStart+8]
		require.Equal(t, "83362e17", swapSelector, "Swap selector must match swap(bytes,bytes,uint256,uint256)")

		// Check offset to fromToken
		fromTokenOffsetHex := hexData[callDataStart+8 : callDataStart+72]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000080", fromTokenOffsetHex, "fromToken offset must be 0x80")

		// Check offset to toToken
		toTokenOffsetHex := hexData[callDataStart+72 : callDataStart+136]
		require.Equal(t, "00000000000000000000000000000000000000000000000000000000000000c0", toTokenOffsetHex, "toToken offset must be 0xc0")

		// Check amountIn (0.01125 * 10^18)
		amountInHex := hexData[callDataStart+136 : callDataStart+200]
		require.Equal(t, "000000000000000000000000000000000000000000000003e733628714200000", amountInHex,
			"amountIn must be 0.01125 ETH")

		// Check minReturn (0.011 * 10^18)
		minReturnHex := hexData[callDataStart+200 : callDataStart+264]
		require.Equal(t, "000000000000000000000000000000000000000000000003dd356e57a5d80000", minReturnHex, "minReturn must be 0.011 ETH")

		// Check fromToken length (20 bytes = 0x14)
		fromTokenLengthHex := hexData[callDataStart+264 : callDataStart+328]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000014", fromTokenLengthHex,
			"fromToken length must be 0x14 (20 bytes)")

		// Check fromToken address
		fromTokenAddressHex := hexData[callDataStart+328 : callDataStart+368]
		require.Equal(t, "2c73996babf1a06c2c057177353293f7ca0907c8", fromTokenAddressHex,
			"fromToken address must match ION token")

		// Check toToken length (20 bytes = 0x14)
		toTokenLengthHex := hexData[callDataStart+392 : callDataStart+456]
		require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000014", toTokenLengthHex,
			"toToken length must be 0x14 (20 bytes)")

		// Check toToken address
		toTokenAddressHex := hexData[callDataStart+456 : callDataStart+496]
		require.Equal(t, "e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb6", toTokenAddressHex,
			"toToken address must match destination token")
	})

	t.Run("extracts_swap_from_handleOps", func(t *testing.T) {
		txInput := "0x74fa412100000000000000000000000000000000000000000000000000000000000000601b071d768b34be2e06c87954537b12eeadab4991131acd5a35e41feff3ae8ddc8a53cdc35a5ffd52c313a3dde16005c2ea88b46dd9d3228363a5ca438a0c037600000000000000000000000000000000000000000000000000000000000001588b5a70a21af8bd7bdb38c0fac5cf3a81079d25950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010483362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000003e733628714200000000000000000000000000000000000000000000000000003dd356e57a5d8000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000014e7ebd115c95248b512c9b0c9fa4bb06b49ffbfb60000000000000000000000000000000000000000"

		topic0 := eventSwapped.Hex()
		contractAddress := "0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595"
		eventData := "0x" +
			"0000000000000000000000000000000000000000000000000000000000000000" + // direction = false (BUY)
			"0000000000000000000000002c73996babf1a06c2c057177353293f7ca0907c8" + // feeToken (ION)
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" + // inputAmount
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000" + // outputAmount
			"0000000000000000000000000000000000000000000000000000000000000000" // fee
		swapperTopic := "0x00000000000000000000000079d7e491506651b776483187ceb5eb75424ae51b"
		pairIdTopic := "0xed22b09fbdfbd285611ec37c49052f6eedca75f6466be5f1ee4a730da8ad8b9c"

		result, err := tokenSwapped(topic0, eventData, contractAddress, swapperTopic, pairIdTopic, txInput)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotNil(t, result.Params, "Params must be extracted from handleOps")

		// Verify extracted swap parameters match Layer 3 data
		fromToken := result.Params["fromToken"].([]byte)
		require.Equal(t, "0x2c73996babf1a06c2c057177353293f7ca0907c8", strings.ToLower(common.BytesToAddress(fromToken).Hex()))

		toToken := result.Params["toToken"].([]byte)
		require.Equal(t, "0xe7ebd115c95248b512c9b0c9fa4bb06b49ffbfb6", strings.ToLower(common.BytesToAddress(toToken).Hex()))

		amountIn := result.Params["amountIn"].(*big.Int)
		require.NotNil(t, amountIn, "amountIn must be extracted from transaction")
		minReturn := result.Params["minReturn"].(*big.Int)
		require.NotNil(t, minReturn, "minReturn must be extracted from transaction")
	})
}

func TestTransferEvent(t *testing.T) {
	t.Run("valid_erc20_transfer", func(t *testing.T) {
		// Transfer(address indexed from, address indexed to, uint256 value)
		tokenAddress := "0x8dC5aa6777F9A6128f8775f93be4bA1a503723AE"
		fromAddr := common.HexToAddress("0xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC")
		toAddr := common.HexToAddress("0x70E06D947F05A6324B12BfE31e2c693a4e369c5E")
		transferAmount := big.NewInt(1000000000000000000) // 1 token (18 decimals)

		// Topics are 32-byte padded addresses
		fromTopic := "0x" + hex.EncodeToString(common.LeftPadBytes(fromAddr.Bytes(), 32))
		toTopic := "0x" + hex.EncodeToString(common.LeftPadBytes(toAddr.Bytes(), 32))

		// Encode data (value is non-indexed)
		data := "0x" + hex.EncodeToString(common.LeftPadBytes(transferAmount.Bytes(), 32))
		event, err := transferEvent(
			eventTransfer.Hex(),
			data,
			tokenAddress,
			fromTopic,
			toTopic,
		)

		require.NoError(t, err)
		require.NotNil(t, event)
		require.Equal(t, strings.ToLower(tokenAddress), strings.ToLower(event.TokenAddress.Hex()))
		require.Equal(t, strings.ToLower(fromAddr.Hex()), strings.ToLower(event.From.Hex()))
		require.Equal(t, strings.ToLower(toAddr.Hex()), strings.ToLower(event.To.Hex()))
		require.Equal(t, transferAmount.String(), event.Value.String())
	})

	t.Run("invalid_signature", func(t *testing.T) {
		_, err := transferEvent(
			"0xinvalid",
			"0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
			"0x8dC5aa6777F9A6128f8775f93be4bA1a503723AE",
			"0x0000000000000000000000000xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC",
			"0x00000000000000000000000070E06D947F05A6324B12BfE31e2c693a4e369c5E",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("empty_data", func(t *testing.T) {
		_, err := transferEvent(
			eventTransfer.Hex(),
			"",
			"0x8dC5aa6777F9A6128f8775f93be4bA1a503723AE",
			"0x0000000000000000000000000xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC",
			"0x00000000000000000000000070E06D947F05A6324B12BfE31e2c693a4e369c5E",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty data")
	})

	t.Run("invalid_data_length", func(t *testing.T) {
		_, err := transferEvent(
			eventTransfer.Hex(),
			"0x1234", // Too short
			"0x8dC5aa6777F9A6128f8775f93be4bA1a503723AE",
			"0x0000000000000000000000000xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC",
			"0x00000000000000000000000070E06D947F05A6324B12BfE31e2c693a4e369c5E",
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid data length")
	})

	t.Run("large_transfer_amount", func(t *testing.T) {
		largeAmount := new(big.Int)
		largeAmount.SetString("1000000000000000000000000", 10) // 1 million tokens

		fromAddr := common.HexToAddress("0xd38D7cDab8802A4Dc5730f9Dfd24464545BB88aC")
		toAddr := common.HexToAddress("0x70E06D947F05A6324B12BfE31e2c693a4e369c5E")
		fromTopic := "0x" + hex.EncodeToString(common.LeftPadBytes(fromAddr.Bytes(), 32))
		toTopic := "0x" + hex.EncodeToString(common.LeftPadBytes(toAddr.Bytes(), 32))

		data := "0x" + hex.EncodeToString(common.LeftPadBytes(largeAmount.Bytes(), 32))

		event, err := transferEvent(
			eventTransfer.Hex(),
			data,
			"0x8dC5aa6777F9A6128f8775f93be4bA1a503723AE",
			fromTopic,
			toTopic,
		)

		require.NoError(t, err)
		require.NotNil(t, event)
		require.Equal(t, largeAmount.String(), event.Value.String())
	})
}
