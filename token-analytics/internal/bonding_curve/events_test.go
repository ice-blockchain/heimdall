//go:build test

// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestTokenSwapped(t *testing.T) {
	t.Run("first_swap_with_fat_address_4param", func(t *testing.T) {
		// First swap (createToken) for digitalocean Finance token
		// TX: 0xae6895486390924c1a6d05df541ae0972672c6c3634506f14e9114e6d3b3e8f5
		txInput := "0x83362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000dbd2fc137a3000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000006d0614137941e0385d6c933a11a705b93b04a728ad80c3a67c0000000000000000000000000000000000000000000000000000000000000000000000000000000052424e5856546469676974616c6f6365616e2046696e616e63653230303331343634373839303330303133393400000000000000000000000000000000000000"

		event, err := tokenSwapped(
			"0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0", // Swapped signature
			"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000",
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",                         // contract
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c", // swapper
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2", // pairId
			txInput,
		)

		require.NoError(t, err, "Should parse first swap (4-param) without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)
		require.Contains(t, event.Params, "fromToken")
		require.Contains(t, event.Params, "toToken")
		require.Contains(t, event.Params, "amountIn")
		require.Contains(t, event.Params, "minReturn")
		// Verify toToken is fat address (> 64 bytes for first swap)
		toToken, ok := event.Params["toToken"].([]byte)
		require.True(t, ok, "toToken should be []byte")
		require.Greater(t, len(toToken), 64, "First swap should have fat address (>64 bytes)")
	})

	t.Run("subsequent_swap_with_thin_address_4param", func(t *testing.T) {
		// Subsequent swap (1+) for the same token - uses thin address (only 20-byte contract address)
		txInput := "0x83362e17000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000001b7a5f826f46000000000000000000000000000000000000000000000000000000000000000000142c73996babf1a06c2c057177353293f7ca0907c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000140f93afe4f21f8885b99932214c66be3ff42e2162000000000000000000000000"

		event, err := tokenSwapped(
			"0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0", // Swapped signature
			"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000001bc16d674ec800000000000000000000000000000000000000000000000000000000000000000000",
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",                         // contract
			"0x00000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c", // swapper
			"0x0f5c7242a0b57acf14eaade14c8e98bbd71ca8f0bc74c76b32eadc4f6b4decf2", // pairId
			txInput,
		)

		require.NoError(t, err, "Should parse subsequent swap (4-param) without error")
		require.NotNil(t, event)
		require.NotNil(t, event.Params)

		require.Contains(t, event.Params, "fromToken")
		require.Contains(t, event.Params, "toToken")
		require.Contains(t, event.Params, "amountIn")
		require.Contains(t, event.Params, "minReturn")

		// Verify toToken is thin address (20 bytes for subsequent swaps)
		toToken, ok := event.Params["toToken"].([]byte)
		require.True(t, ok, "toToken should be []byte")
		require.Equal(t, 20, len(toToken), "Subsequent swap should have thin address (20 bytes)")
	})

	t.Run("swap_with_permit_5param", func(t *testing.T) {
		// Proper ABI encoding for 5-param swap:
		// 1. Function selector: 0x83362e17 (4 bytes)
		// 2. Offset to fromToken (bytes - dynamic type)
		// 3. Offset to toToken (bytes - dynamic type)
		// 4. amountIn (uint256 - static)
		// 5. minReturn (uint256 - static)
		// 6. PermitData INLINE (5 * 32 bytes = 160 bytes):
		//    - value (uint256)
		//    - deadline (uint256)
		//    - v (uint8, padded to 32 bytes)
		//    - r (bytes32)
		//    - s (bytes32)
		// 7. fromToken data (at calculated offset)
		// 8. toToken data (at calculated offset)

		// Head size: 4 (selector) + 2*32 (offsets) + 2*32 (static params) + 5*32 (permit inline) = 4 + 64 + 64 + 160 = 292 bytes
		// fromToken offset: 292 (0x124)
		// toToken offset: 292 + 32 + 32 = 356 (0x164) - after fromToken length and data
		txInput := "0x027c101d000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000055de6a779bbac00000000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000000000000065a0c5a0000000000000000000000000000000000000000000000000000000000000001b12131415161718191a1b1c1d1e1f202112131415161718191a1b1c1d1e1f2021fefdfcfbfaf9f8f7f6f5f4f3f2f1f0effefdfcfbfaf9f8f7f6f5f4f3f2f1f0ef0000000000000000000000000000000000000000000000000000000000000014fffe00ab26d8d121a51717306adbebc70b8b7247000000000000000000000000000000000000000000000000000000000000000000000000000000000000001425c4b7a88c2d4be2558cf3ba68d42e0b46cbe388000000000000000000000000"

		event, err := tokenSwapped(
			"0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0", // Swapped signature
			"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000008ac7230489e800000000000000000000000000000000000000000000000000000000000000000000",
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",                         // contract
			"0x0000000000000000000000005a4cab6a30022c31534c2ada02c6ac1539d01944", // swapper
			"0x0ea54805a12e72704b43361c6fb763c75ecf380a696f294b903a6909ef918530", // pairId
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
}

func TestTokenCreated(t *testing.T) {
	t.Run("valid_token_created", func(t *testing.T) {
		// BondingTokenCreated event for "digitalocean Finance" (RBNXVT) token
		data := "0x0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079000000000000000000000000000000000000000000000000000000000000018000000000000000000000000041e0385d6c933a11a705b93b04a728ad80c3a67c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000033b2e3c9fd0803ce800000000000000000000000000000000000000000000000000000000000000000000146469676974616c6f6365616e2046696e616e6365000000000000000000000000000000000000000000000000000000000000000000000000000000000000000652424e585654000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000133230303331343634373839303330303133393400000000000000000000000000"

		event, err := tokenCreated(
			eventTokenCreated.Hex(),
			data,
			"0x8b5a70a21af8bd7bdb38c0fac5cf3a81079d2595",
			"0x0000000000000000000000000f93afe4f21f8885b99932214c66be3ff42e2162",
		)

		require.NoError(t, err, "Should parse TokenCreated event without error")
		require.NotNil(t, event)
		require.Equal(t, strings.ToLower("0x0f93afe4f21f8885b99932214c66be3ff42e2162"), strings.ToLower(event.Address.Hex()))
		require.Equal(t, "digitalocean Finance", event.Name)
		require.Equal(t, "RBNXVT", event.Symbol)
		require.NotNil(t, event.TotalSupply)
		require.Equal(t, uint8(0x79), event.ExternalType)              // externalType = 121 (0x79)
		require.Equal(t, "2003146478903001394", event.ExternalAddress) // Twitter user ID
		require.Equal(t, strings.ToLower("0x41e0385d6c933a11a705b93b04a728ad80c3a67c"), strings.ToLower(event.CreatorAddress.Hex()))
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

		event, err := pairRegistered(
			eventPairRegistered.Hex(),
			"0x",
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
