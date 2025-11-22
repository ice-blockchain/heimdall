// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildTopHolderPositions(t *testing.T) {
	t.Parallel()

	contractAddr := "0xcontract123"

	t.Run("should build positions with complete data", func(t *testing.T) {
		t.Parallel()

		rankings := []redis.Z{
			{Score: 1.0005, Member: "pubkey1"},  // 1.0005 tokens
			{Score: 0.50025, Member: "pubkey2"}, // 0.50025 tokens
			{Score: 0.1, Member: "pubkey3"},     // 0.1 tokens
		}

		rows := []*holderWithTokenData{
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator_user",
				CreatorDisplay:      "Creator Name",
				CreatorVerified:     true,
				CreatorAvatar:       "https://avatar.com/creator.jpg",
				PriceUSD:            1.5,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(), // 100 tokens
				HolderMasterPubkey:  "pubkey1",
				HolderUsername:      "holder1",
				HolderDisplay:       "Holder One",
				HolderVerified:      true,
				HolderAvatar:        "https://avatar.com/holder1.jpg",
			},
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator_user",
				CreatorDisplay:      "Creator Name",
				CreatorVerified:     true,
				CreatorAvatar:       "https://avatar.com/creator.jpg",
				PriceUSD:            1.5,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:  "pubkey2",
				HolderUsername:      "holder2",
				HolderDisplay:       "Holder Two",
				HolderVerified:      false,
				HolderAvatar:        "https://avatar.com/holder2.jpg",
			},
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator_user",
				CreatorDisplay:      "Creator Name",
				CreatorVerified:     true,
				CreatorAvatar:       "https://avatar.com/creator.jpg",
				PriceUSD:            1.5,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:  "pubkey3",
				HolderUsername:      "holder3",
				HolderDisplay:       "Holder Three",
				HolderVerified:      false,
				HolderAvatar:        "",
			},
		}

		result := buildTopHolderPositions(contractAddr, rankings, rows)
		require.Len(t, result, 3)
		assert.Equal(t, uint64(1), result[0].Position.Rank)
		assert.Equal(t, "holder1", result[0].Position.Holder.Username)
		assert.Equal(t, "pubkey1", result[0].Position.Holder.MasterPubkey)
		assert.Equal(t, uint64(1.0005e18), result[0].Position.Amount)
		assert.Equal(t, 1.50075, result[0].Position.AmountUSD)  // 1.0005 tokens * 1.5 USD
		assert.Equal(t, 1.0005, result[0].Position.SupplyShare) // 1.0005 / 100 * 100
		assert.Equal(t, "0:pubkey1:", result[0].Position.Holder.IonConnect)
		assert.True(t, result[0].Position.Holder.Verified)

		assert.Equal(t, "creator_user", result[0].Creator.Username)
		assert.Equal(t, "Creator Name", result[0].Creator.Display)
		assert.Equal(t, "0:creator_pubkey:", result[0].Creator.IonConnect)
		assert.True(t, result[0].Creator.Verified)

		assert.Equal(t, uint64(2), result[1].Position.Rank)
		assert.Equal(t, "holder2", result[1].Position.Holder.Username)
		assert.Equal(t, uint64(5.0025e17), result[1].Position.Amount)
		assert.Equal(t, 0.750375, result[1].Position.AmountUSD)  // 0.50025 tokens * 1.5 USD
		assert.Equal(t, 0.50025, result[1].Position.SupplyShare) // 0.50025 / 100 * 100
		assert.False(t, result[1].Position.Holder.Verified)

		assert.Equal(t, uint64(3), result[2].Position.Rank)
		assert.Equal(t, "holder3", result[2].Position.Holder.Username)
		assert.Equal(t, uint64(1.0e17), result[2].Position.Amount)
		assert.Equal(t, 0.15000000000000002, result[2].Position.AmountUSD) // 0.1 tokens * 1.5 USD
		assert.Equal(t, 0.1, result[2].Position.SupplyShare)               // 0.1 / 100 * 100
		assert.Empty(t, result[2].Position.Holder.Avatar)
	})

	t.Run("should handle empty rankings", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{}
		rows := []*holderWithTokenData{}
		assert.Empty(t, buildTopHolderPositions(contractAddr, rankings, rows))
	})

	t.Run("should skip holder when data not found in rows", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{
			{Score: 1.0, Member: "pubkey1"},
			{Score: 0.5, Member: "pubkey_missing"},
			{Score: 0.1, Member: "pubkey3"},
		}
		rows := []*holderWithTokenData{
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:  "pubkey1",
				HolderUsername:      "user1",
			},
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:  "pubkey3",
				HolderUsername:      "user3",
			},
		}

		result := buildTopHolderPositions(contractAddr, rankings, rows)
		require.Len(t, result, 2)
		assert.Equal(t, "user1", result[0].Position.Holder.Username)
		assert.Equal(t, "user3", result[1].Position.Holder.Username)
	})

	t.Run("should calculate correct supply share percentages", func(t *testing.T) {
		t.Parallel()

		totalSupply := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 tokens

		rankings := []redis.Z{
			{Score: 5.0, Member: "pubkey1"}, // 5 tokens = 50%
			{Score: 3.0, Member: "pubkey2"}, // 3 tokens = 30%
			{Score: 2.0, Member: "pubkey3"}, // 2 tokens = 20%
		}

		rows := []*holderWithTokenData{
			{
				CreatorMasterPubkey: "creator",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         totalSupply.String(),
				HolderMasterPubkey:  "pubkey1",
				HolderUsername:      "user1",
			},
			{
				CreatorMasterPubkey: "creator",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         totalSupply.String(),
				HolderMasterPubkey:  "pubkey2",
				HolderUsername:      "user2",
			},
			{
				CreatorMasterPubkey: "creator",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         totalSupply.String(),
				HolderMasterPubkey:  "pubkey3",
				HolderUsername:      "user3",
			},
		}

		result := buildTopHolderPositions(contractAddr, rankings, rows)

		require.Len(t, result, 3)
		assert.Equal(t, 50.0, result[0].Position.SupplyShare)
		assert.Equal(t, 30.0, result[1].Position.SupplyShare)
		assert.Equal(t, 20.0, result[2].Position.SupplyShare)
	})
}
