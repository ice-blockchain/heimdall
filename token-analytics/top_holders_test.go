// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func Test_buildTopHolderPositions(t *testing.T) {

	contractAddr := "0xcontract123"

	t.Run("should build positions with complete data", func(t *testing.T) {
		t.Parallel()

		rankings := []redis.Z{
			{Score: 1.0005, Member: "0:pubkey1:"},  // 1.0005 tokens
			{Score: 0.50025, Member: "0:pubkey2:"}, // 0.50025 tokens
			{Score: 0.1, Member: "0:pubkey3:"},     // 0.1 tokens
		}

		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("0:creator_ext:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.5,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(), // 100 tokens
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("holder1"),
				HolderDisplay:          strPtr("Holder One"),
				HolderVerified:         boolPtr(true),
				HolderAvatar:           strPtr("https://avatar.com/holder1.jpg"),
				HolderExternalAddress:  strPtr("0:pubkey1:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("0:creator_ext:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.5,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:     strPtr("pubkey2"),
				HolderUsername:         strPtr("holder2"),
				HolderDisplay:          strPtr("Holder Two"),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr("https://avatar.com/holder2.jpg"),
				HolderExternalAddress:  strPtr("0:pubkey2:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("0:creator_ext:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.5,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:     strPtr("pubkey3"),
				HolderUsername:         strPtr("holder3"),
				HolderDisplay:          strPtr("Holder Three"),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("0:pubkey3:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rows, "", "", 0)
		require.NoError(t, err)
		require.Len(t, result, 3)
		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "holder1", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "pubkey1", strVal(result[0].Position.Holder.MasterPubkey))
		require.Equal(t, "1000500000000000000", result[0].Position.Amount) // 1.0005 tokens * 1e18
		require.Equal(t, 1.50075, result[0].Position.AmountUSD)            // 1.0005 tokens * 1.5 USD
		require.Equal(t, 1.0005, result[0].Position.SupplyShare)           // 1.0005 / 100 * 100
		require.Equal(t, "pubkey1", result[0].Position.Holder.Addresses.IonConnect)
		require.True(t, *result[0].Position.Holder.Verified)

		require.Equal(t, "creator_user", strVal(result[0].Creator.Username))
		require.Equal(t, "Creator Name", strVal(result[0].Creator.Display))
		require.Equal(t, "creator_ext", result[0].Creator.Addresses.IonConnect)
		require.True(t, *result[0].Creator.Verified)

		require.Equal(t, uint64(2), result[1].Position.Rank)
		require.Equal(t, "holder2", strVal(result[1].Position.Holder.Username))
		require.Equal(t, "500250000000000000", result[1].Position.Amount) // 0.50025 tokens * 1e18
		require.Equal(t, 0.750375, result[1].Position.AmountUSD)          // 0.50025 tokens * 1.5 USD
		require.Equal(t, 0.50025, result[1].Position.SupplyShare)         // 0.50025 / 100 * 100
		require.False(t, *result[1].Position.Holder.Verified)

		require.Equal(t, uint64(3), result[2].Position.Rank)
		require.Equal(t, "holder3", strVal(result[2].Position.Holder.Username))
		require.Equal(t, "100000000000000000", result[2].Position.Amount)   // 0.1 tokens * 1e18
		require.Equal(t, 0.15000000000000002, result[2].Position.AmountUSD) // 0.1 tokens * 1.5 USD
		require.Equal(t, 0.1, result[2].Position.SupplyShare)               // 0.1 / 100 * 100
		require.Empty(t, result[2].Position.Holder.Avatar)
	})

	t.Run("should handle empty rankings", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{}
		rows := []*holderWithTokenData{}
		result, err := buildTopHolderPositions(contractAddr, rankings, rows, "", "", 0)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("should skip holder when data not found in rows", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{
			{Score: 1.0, Member: "0:test_holder1:"},
			{Score: 0.5, Member: "0:pubkey_missing:"},
			{Score: 0.1, Member: "0:test_holder3:"},
		}
		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("0:test_creator:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("user1"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("0:test_holder1:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("0:test_creator:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:     strPtr("pubkey3"),
				HolderUsername:         strPtr("user3"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("0:test_holder3:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rows, "", "", 0)
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.Equal(t, "user1", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "user3", strVal(result[1].Position.Holder.Username))
	})

	t.Run("should calculate correct supply share percentages", func(t *testing.T) {
		t.Parallel()

		totalSupply := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 tokens

		rankings := []redis.Z{
			{Score: 5.0, Member: "0:test_holder1:"}, // 5 tokens = 50%
			{Score: 3.0, Member: "0:test_holder2:"}, // 3 tokens = 30%
			{Score: 2.0, Member: "0:test_holder3:"}, // 2 tokens = 20%
		}

		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("0:test_creator:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("user1"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("0:test_holder1:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("0:test_creator:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				HolderMasterPubkey:     strPtr("pubkey2"),
				HolderUsername:         strPtr("user2"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("0:test_holder2:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("0:test_creator:"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				HolderMasterPubkey:     strPtr("pubkey3"),
				HolderUsername:         strPtr("user3"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("0:test_holder3:"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rows, "", "", 0)
		require.NoError(t, err)

		require.Len(t, result, 3)
		require.Equal(t, 50.0, result[0].Position.SupplyShare)
		require.Equal(t, 30.0, result[1].Position.SupplyShare)
		require.Equal(t, 20.0, result[2].Position.SupplyShare)
	})
}
