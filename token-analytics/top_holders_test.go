// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	bondingcurvefixture "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
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
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("creator_ext"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.5,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(), // 100 tokens
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("holder1"),
				HolderDisplay:          strPtr("Holder One"),
				HolderVerified:         boolPtr(true),
				HolderAvatar:           strPtr("https://avatar.com/holder1.jpg"),
				HolderExternalAddress:  strPtr("pubkey1"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("creator_ext"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.5,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey2"),
				HolderUsername:         strPtr("holder2"),
				HolderDisplay:          strPtr("Holder Two"),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr("https://avatar.com/holder2.jpg"),
				HolderExternalAddress:  strPtr("pubkey2"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("creator_ext"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.5,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey3"),
				HolderUsername:         strPtr("holder3"),
				HolderDisplay:          strPtr("Holder Three"),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("pubkey3"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		burnAddr := "0xburn456"
		bondingCurveAddr := "0xbonding789"
		burnedRow := &holderWithTokenData{
			ContentAuthorID:        strPtr("creator_pubkey"),
			CreatorUsername:        strPtr("creator_user"),
			CreatorDisplay:         strPtr("Creator Name"),
			CreatorVerified:        boolPtr(true),
			CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
			CreatorExternalAddress: strPtr("creator_ext"),
			CreatorPlatform:        strPtr("ionconnect"),
			PriceUSD:               1.5,
			TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
			TokenType:              TokenTypeProfile,
			TokenPlatform:          PlatformGroupIonConnect,
			HolderExternalAddress:  &burnAddr,
			HolderBnbBscAddress:    &burnAddr,
			HolderPlatform:         strPtr("ionconnect"),
			HolderDisplay:          strPtr("Burned"),
			HolderVerified:         boolPtr(false),
		}
		rowsWithBurned := append(rows, burnedRow)
		rankingsWithBurned := append(rankings, redis.Z{Score: 0.05, Member: burnAddr})

		result, err := buildTopHolderPositions(contractAddr, rankingsWithBurned, []redis.Z{}, rowsWithBurned, bondingCurveAddr, burnAddr)
		require.NoError(t, err)
		require.Len(t, result, 4, "Profile token should include burned holder")
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

		require.Equal(t, uint64(0), result[3].Position.Rank, "Burned holder should have rank 0")
		require.Equal(t, "Burned", strVal(result[3].Position.Holder.Display))
		require.Equal(t, burnAddr, result[3].Position.Holder.Addresses.Blockchain)
	})

	t.Run("should handle empty rankings", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{}
		rows := []*holderWithTokenData{}
		result, err := buildTopHolderPositions(contractAddr, rankings, []redis.Z{}, rows, "", "")
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("should build position when holder not in users table yet", func(t *testing.T) {
		t.Parallel()
		burnAddr := "0xburn123"
		rankings := []redis.Z{
			{Score: 1.5, Member: "new_holder_pubkey"},
		}
		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator_pubkey"),
				CreatorUsername:        strPtr("creator_user"),
				CreatorDisplay:         strPtr("Creator Name"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/creator.jpg"),
				CreatorExternalAddress: strPtr("creator_ext"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               2.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypePost,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderExternalAddress:  strPtr("new_holder_pubkey"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}
		result, err := buildTopHolderPositions(contractAddr, rankings, []redis.Z{}, rows, "", burnAddr)
		require.NoError(t, err)
		require.Len(t, result, 1, "IonConnect content token should NOT include burned holder")

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "1500000000000000000", result[0].Position.Amount) // 1.5 tokens * 1e18
		require.Equal(t, 3.0, result[0].Position.AmountUSD)                // 1.5 tokens * 2.0 USD
		require.Equal(t, 1.5, result[0].Position.SupplyShare)              // 1.5 / 100 * 100

		require.NotNil(t, result[0].Position.Holder)
		require.NotNil(t, result[0].Position.Holder.Addresses)
		require.Equal(t, "new_holder_pubkey", result[0].Position.Holder.Addresses.IonConnect)

		require.Nil(t, result[0].Position.Holder.Username)
		require.Nil(t, result[0].Position.Holder.Display)
		require.Nil(t, result[0].Position.Holder.Verified)
		require.Nil(t, result[0].Position.Holder.Avatar)
	})

	t.Run("should build position when holder not in users table yet - xcom token", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{
			{Score: 2.5, Member: "987654321"},
		}
		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator_xcom"),
				CreatorUsername:        strPtr("creator_xcom_user"),
				CreatorDisplay:         strPtr("Creator X.com"),
				CreatorVerified:        boolPtr(true),
				CreatorAvatar:          strPtr("https://avatar.com/xcom_creator.jpg"),
				CreatorExternalAddress: strPtr("123456789"),
				CreatorPlatform:        strPtr("xcom"),
				PriceUSD:               3.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupXCom,
				HolderExternalAddress:  strPtr("987654321"),
				HolderPlatform:         strPtr("xcom"),
			},
		}
		result, err := buildTopHolderPositions(contractAddr, rankings, []redis.Z{}, rows, "", "")
		require.NoError(t, err)
		require.Len(t, result, 1, "Should build position even when holder not in users table for X.com token")

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "2500000000000000000", result[0].Position.Amount) // 2.5 tokens * 1e18
		require.Equal(t, 7.5, result[0].Position.AmountUSD)                // 2.5 tokens * 3.0 USD
		require.Equal(t, 1.25, result[0].Position.SupplyShare)             // 2.5 / 200 * 100

		require.NotNil(t, result[0].Position.Holder)
		require.NotNil(t, result[0].Position.Holder.Addresses)
		require.Equal(t, "987654321", result[0].Position.Holder.Addresses.Twitter)
		require.Empty(t, result[0].Position.Holder.Addresses.IonConnect)

		require.Nil(t, result[0].Position.Holder.Username)
		require.Nil(t, result[0].Position.Holder.Display)
		require.Nil(t, result[0].Position.Holder.Verified)
		require.Nil(t, result[0].Position.Holder.Avatar)
	})

	t.Run("should handle mixed ionconnect and xcom holders", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{
			{Score: 10.0, Member: "ionholder1"},
			{Score: 5.0, Member: "123456789"},
			{Score: 2.0, Member: "ionholder2"},
		}
		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("ion_user1"),
				HolderDisplay:          strPtr("Ion User 1"),
				HolderVerified:         boolPtr(true),
				HolderExternalAddress:  strPtr("ionholder1"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey2"),
				HolderUsername:         strPtr("xcom_user"),
				HolderDisplay:          strPtr("X User"),
				HolderVerified:         boolPtr(false),
				HolderExternalAddress:  strPtr("123456789"),
				HolderPlatform:         strPtr("xcom"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey3"),
				HolderUsername:         strPtr("ion_user2"),
				HolderDisplay:          strPtr("Ion User 2"),
				HolderVerified:         boolPtr(false),
				HolderExternalAddress:  strPtr("ionholder2"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, []redis.Z{}, rows, "", "")
		require.NoError(t, err)
		require.Len(t, result, 3)

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "ion_user1", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "ionholder1", result[0].Position.Holder.Addresses.IonConnect)
		require.Empty(t, result[0].Position.Holder.Addresses.Twitter)

		require.Equal(t, uint64(2), result[1].Position.Rank)
		require.Equal(t, "xcom_user", strVal(result[1].Position.Holder.Username))
		require.Equal(t, "123456789", result[1].Position.Holder.Addresses.Twitter)
		require.Empty(t, result[1].Position.Holder.Addresses.IonConnect)

		require.Equal(t, uint64(3), result[2].Position.Rank)
		require.Equal(t, "ion_user2", strVal(result[2].Position.Holder.Username))
		require.Equal(t, "ionholder2", result[2].Position.Holder.Addresses.IonConnect)
		require.Empty(t, result[2].Position.Holder.Addresses.Twitter)
	})

	t.Run("should handle zero price correctly", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{
			{Score: 10.0, Member: "holder1"},
		}
		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				TotalSupply:            new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("user1"),
				HolderVerified:         boolPtr(false),
				HolderExternalAddress:  strPtr("holder1"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, []redis.Z{}, rows, "", "")
		require.NoError(t, err)
		require.Len(t, result, 1)
		require.Equal(t, 0.0, result[0].Position.AmountUSD)
	})

	t.Run("should calculate correct supply share percentages", func(t *testing.T) {
		t.Parallel()

		totalSupply := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 tokens

		rankings := []redis.Z{
			{Score: 5.0, Member: "test_holder1"}, // 5 tokens = 50%
			{Score: 3.0, Member: "test_holder2"}, // 3 tokens = 30%
			{Score: 2.0, Member: "test_holder3"}, // 2 tokens = 20%
		}

		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("test_creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey1"),
				HolderUsername:         strPtr("user1"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("test_holder1"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("test_creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey2"),
				HolderUsername:         strPtr("user2"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("test_holder2"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr(""),
				CreatorVerified:        boolPtr(false),
				CreatorAvatar:          strPtr(""),
				CreatorExternalAddress: strPtr("test_creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("pubkey3"),
				HolderUsername:         strPtr("user3"),
				HolderDisplay:          strPtr(""),
				HolderVerified:         boolPtr(false),
				HolderAvatar:           strPtr(""),
				HolderExternalAddress:  strPtr("test_holder3"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, []redis.Z{}, rows, "", "")
		require.NoError(t, err)

		require.Len(t, result, 3)
		require.Equal(t, 50.0, result[0].Position.SupplyShare)
		require.Equal(t, 30.0, result[1].Position.SupplyShare)
		require.Equal(t, 20.0, result[2].Position.SupplyShare)
	})

	t.Run("should assign unique ranks when holders come from both rankings lists", func(t *testing.T) {
		t.Parallel()

		totalSupply := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

		rankings := []redis.Z{
			{Score: 40.0, Member: "holder1"},
			{Score: 30.0, Member: "holder2"},
		}

		rankingsByBlockchain := []redis.Z{
			{Score: 25.0, Member: "0xblockchain3"},
			{Score: 20.0, Member: "0xblockchain4"},
		}

		rows := []*holderWithTokenData{
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr("Creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("holder1"),
				HolderUsername:         strPtr("user1"),
				HolderDisplay:          strPtr("User 1"),
				HolderVerified:         boolPtr(false),
				HolderExternalAddress:  strPtr("holder1"),
				HolderBnbBscAddress:    strPtr("0xblockchain1"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr("Creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     strPtr("holder2"),
				HolderUsername:         strPtr("user2"),
				HolderDisplay:          strPtr("User 2"),
				HolderVerified:         boolPtr(false),
				HolderExternalAddress:  strPtr("holder2"),
				HolderBnbBscAddress:    strPtr("0xblockchain2"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr("Creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     nil,
				HolderUsername:         nil,
				HolderDisplay:          nil,
				HolderVerified:         nil,
				HolderBnbBscAddress:    strPtr("0xblockchain3"),
				HolderPlatform:         strPtr("ionconnect"),
			},
			{
				ContentAuthorID:        strPtr("creator"),
				CreatorUsername:        strPtr("creator"),
				CreatorDisplay:         strPtr("Creator"),
				CreatorVerified:        boolPtr(false),
				CreatorExternalAddress: strPtr("creator"),
				CreatorPlatform:        strPtr("ionconnect"),
				PriceUSD:               1.0,
				TotalSupply:            totalSupply.String(),
				TokenType:              TokenTypeProfile,
				TokenPlatform:          PlatformGroupIonConnect,
				HolderMasterPubkey:     nil,
				HolderUsername:         nil,
				HolderDisplay:          nil,
				HolderVerified:         nil,
				HolderBnbBscAddress:    strPtr("0xblockchain4"),
				HolderPlatform:         strPtr("ionconnect"),
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rankingsByBlockchain, rows, "", "")
		require.NoError(t, err)
		require.Len(t, result, 4)

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "user1", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "40000000000000000000", result[0].Position.Amount)

		require.Equal(t, uint64(2), result[1].Position.Rank)
		require.Equal(t, "user2", strVal(result[1].Position.Holder.Username))
		require.Equal(t, "30000000000000000000", result[1].Position.Amount)

		require.Equal(t, uint64(3), result[2].Position.Rank)
		require.Equal(t, "0xblockchain3", result[2].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "25000000000000000000", result[2].Position.Amount)

		require.Equal(t, uint64(4), result[3].Position.Rank)
		require.Equal(t, "0xblockchain4", result[3].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "20000000000000000000", result[3].Position.Amount)
	})
}

func TestGetTopHolders(t *testing.T) {
	t.Parallel()

	t.Run("should return top holders with bonding curve and burned for profile token", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		bondingGoal, _ := new(big.Int).SetString("1000000000000000000000", 10)
		soldTokens, _ := new(big.Int).SetString("500000000000000000000", 10)
		config := &bondingcurvefixture.MockBackendConfig{
			BuyPrice:          big.NewInt(950000000000000000),
			SellPrice:         big.NewInt(1050000000000000000),
			SoldTokens:        soldTokens,
			TokensRaised:      big.NewInt(0),
			StartPrice:        big.NewInt(100000000000000000),
			EndPrice:          big.NewInt(200000000000000000),
			BondingTokensGoal: bondingGoal,
			CurrentPrice:      big.NewInt(150000000000000000),
			Migrated:          false,
		}
		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, config)
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator123"
		creatorBlockchainAddr := "0x1111111111111111111111111111111111111111"
		tokenContractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		tokenExternalAddr := "0:creator123:token1"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000001"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator", "Creator User", creatorBlockchainAddr, true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "CRTK", TokenTypeProfile, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 2.0)

		holder1MasterPubkey := "holder1"
		holder1ExternalAddr := "holder1"
		holder1BlockchainAddr := "0x2222222222222222222222222222222222222222"
		holder2MasterPubkey := "holder2"
		holder2ExternalAddr := "holder2"
		holder2BlockchainAddr := "0x3333333333333333333333333333333333333333"
		holder3MasterPubkey := "holder3"
		holder3ExternalAddr := "holder3"
		holder3BlockchainAddr := "0x4444444444444444444444444444444444444444"

		helperInsertTestUser(t, ctx, db, holder1MasterPubkey, "holder1", "Holder One", holder1BlockchainAddr, true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, holder2MasterPubkey, "holder2", "Holder Two", holder2BlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, holder3MasterPubkey, "holder3", "Holder Three", holder3BlockchainAddr, false, PlatformGroupIonConnect)

		helperInsertUserTokenPosition(t, ctx, db, holder1MasterPubkey, tokenContractAddr, tokenExternalAddr, holder1ExternalAddr, "10000000000000000000", 2.0, 20.0)
		helperInsertUserTokenPosition(t, ctx, db, holder2MasterPubkey, tokenContractAddr, tokenExternalAddr, holder2ExternalAddr, "5000000000000000000", 2.0, 10.0)
		helperInsertUserTokenPosition(t, ctx, db, holder3MasterPubkey, tokenContractAddr, tokenExternalAddr, holder3ExternalAddr, "2000000000000000000", 2.0, 4.0)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 10.0, Member: holder1ExternalAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 5.0, Member: holder2ExternalAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 2.0, Member: holder3ExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 10.0, Member: holder1BlockchainAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 5.0, Member: holder2BlockchainAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 2.0, Member: holder3BlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 5, len(result))

		require.Equal(t, uint64(0), result[0].Position.Rank)
		require.Equal(t, "Bonding Curve", strVal(result[0].Position.Holder.Display))
		require.Equal(t, "500000000000000000000", result[0].Position.Amount)
		require.NotNil(t, result[0].Position.Holder.Avatar)
		require.Equal(t, ta.cfg.BondingCurve.SmartContractAddress, result[0].Position.Holder.Addresses.Blockchain)

		require.Equal(t, uint64(0), result[1].Position.Rank)
		require.Equal(t, "Burned", strVal(result[1].Position.Holder.Display))
		require.NotNil(t, result[1].Position.Holder.Avatar)
		require.Equal(t, ta.cfg.BondingCurve.BurnAddress, result[1].Position.Holder.Addresses.Blockchain)

		require.Equal(t, uint64(1), result[2].Position.Rank)
		require.Equal(t, "holder1", strVal(result[2].Position.Holder.Username))
		require.Equal(t, "Holder One", strVal(result[2].Position.Holder.Display))
		require.True(t, *result[2].Position.Holder.Verified)
		require.NotNil(t, result[2].Position.Holder.Avatar)
		require.Equal(t, holder1MasterPubkey, result[2].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder1BlockchainAddr, result[2].Position.Holder.Addresses.Blockchain)
		require.Empty(t, result[2].Position.Holder.Addresses.Twitter)
		require.Equal(t, "10000000000000000000", result[2].Position.Amount)
		require.Equal(t, 20.0, result[2].Position.AmountUSD)
		require.Equal(t, 1.0, result[2].Position.SupplyShare)

		require.Equal(t, "creator", strVal(result[2].Creator.Username))
		require.Equal(t, "Creator User", strVal(result[2].Creator.Display))
		require.True(t, *result[2].Creator.Verified)
		require.NotNil(t, result[2].Creator.Avatar)
		require.Equal(t, creatorMasterPubkey, result[2].Creator.Addresses.IonConnect)
		require.Equal(t, creatorBlockchainAddr, result[2].Creator.Addresses.Blockchain)
		require.Empty(t, result[2].Creator.Addresses.Twitter)

		require.Equal(t, uint64(2), result[3].Position.Rank)
		require.Equal(t, "holder2", strVal(result[3].Position.Holder.Username))
		require.Equal(t, "Holder Two", strVal(result[3].Position.Holder.Display))
		require.False(t, *result[3].Position.Holder.Verified)
		require.Equal(t, holder2MasterPubkey, result[3].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder2BlockchainAddr, result[3].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "5000000000000000000", result[3].Position.Amount)
		require.Equal(t, 10.0, result[3].Position.AmountUSD)
		require.Equal(t, 0.5, result[3].Position.SupplyShare)

		require.Equal(t, uint64(3), result[4].Position.Rank)
		require.Equal(t, "holder3", strVal(result[4].Position.Holder.Username))
		require.Equal(t, "Holder Three", strVal(result[4].Position.Holder.Display))
		require.False(t, *result[4].Position.Holder.Verified)
		require.Equal(t, holder3MasterPubkey, result[4].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder3BlockchainAddr, result[4].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "2000000000000000000", result[4].Position.Amount)
		require.Equal(t, 4.0, result[4].Position.AmountUSD)
		require.Equal(t, 0.2, result[4].Position.SupplyShare)
	})

	t.Run("should return content token holders with bonding curve without burned", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		bondingGoal, _ := new(big.Int).SetString("1000000000000000000000", 10)
		soldTokens, _ := new(big.Int).SetString("300000000000000000000", 10)
		config := &bondingcurvefixture.MockBackendConfig{
			BuyPrice:          big.NewInt(950000000000000000),
			SellPrice:         big.NewInt(1050000000000000000),
			SoldTokens:        soldTokens,
			TokensRaised:      big.NewInt(0),
			StartPrice:        big.NewInt(100000000000000000),
			EndPrice:          big.NewInt(200000000000000000),
			BondingTokensGoal: bondingGoal,
			CurrentPrice:      big.NewInt(150000000000000000),
			Migrated:          false,
		}
		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, config)
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator_content"
		creatorBlockchainAddr := "0xaaaa000000000000000000000000000000000000"
		tokenContractAddr := "0xcccccccccccccccccccccccccccccccccccccccc"
		tokenExternalAddr := "0:creator_content:token_content"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000008"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator_content", "Creator Content", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TCNT", TokenTypePost, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 1.5)

		holder1MasterPubkey := "holder_content1"
		holder1ExternalAddr := "holder_content1"
		holder1BlockchainAddr := "0xbbbb000000000000000000000000000000000000"
		holder2MasterPubkey := "holder_content2"
		holder2ExternalAddr := "holder_content2"
		holder2BlockchainAddr := "0xcccc000000000000000000000000000000000000"

		helperInsertTestUser(t, ctx, db, holder1MasterPubkey, "holder_content1", "Holder Content 1", holder1BlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, holder2MasterPubkey, "holder_content2", "Holder Content 2", holder2BlockchainAddr, false, PlatformGroupIonConnect)

		helperInsertUserTokenPosition(t, ctx, db, holder1MasterPubkey, tokenContractAddr, tokenExternalAddr, holder1ExternalAddr, "8000000000000000000", 1.5, 12.0)
		helperInsertUserTokenPosition(t, ctx, db, holder2MasterPubkey, tokenContractAddr, tokenExternalAddr, holder2ExternalAddr, "3000000000000000000", 1.5, 4.5)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 8.0, Member: holder1ExternalAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 3.0, Member: holder2ExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 8.0, Member: holder1BlockchainAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 3.0, Member: holder2BlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))

		require.Equal(t, uint64(0), result[0].Position.Rank)
		require.Equal(t, "Bonding Curve", strVal(result[0].Position.Holder.Display))
		require.Equal(t, "700000000000000000000", result[0].Position.Amount)
		require.NotNil(t, result[0].Position.Holder.Avatar)
		require.Equal(t, ta.cfg.BondingCurve.SmartContractAddress, result[0].Position.Holder.Addresses.Blockchain)

		require.Equal(t, uint64(1), result[1].Position.Rank)
		require.Equal(t, "holder_content1", strVal(result[1].Position.Holder.Username))
		require.Equal(t, "Holder Content 1", strVal(result[1].Position.Holder.Display))
		require.False(t, *result[1].Position.Holder.Verified)
		require.NotNil(t, result[1].Position.Holder.Avatar)
		require.Equal(t, holder1MasterPubkey, result[1].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder1BlockchainAddr, result[1].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "8000000000000000000", result[1].Position.Amount)
		require.InDelta(t, 12.0, result[1].Position.AmountUSD, 0.0001)
		require.InDelta(t, 0.8, result[1].Position.SupplyShare, 0.0001)

		require.Equal(t, "creator_content", strVal(result[1].Creator.Username))
		require.Equal(t, "Creator Content", strVal(result[1].Creator.Display))
		require.False(t, *result[1].Creator.Verified)
		require.Equal(t, creatorMasterPubkey, result[1].Creator.Addresses.IonConnect)
		require.Equal(t, creatorBlockchainAddr, result[1].Creator.Addresses.Blockchain)

		require.Equal(t, uint64(2), result[2].Position.Rank)
		require.Equal(t, "holder_content2", strVal(result[2].Position.Holder.Username))
		require.Equal(t, "Holder Content 2", strVal(result[2].Position.Holder.Display))
		require.False(t, *result[2].Position.Holder.Verified)
		require.Equal(t, holder2MasterPubkey, result[2].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder2BlockchainAddr, result[2].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "3000000000000000000", result[2].Position.Amount)
		require.InDelta(t, 4.5, result[2].Position.AmountUSD, 0.0001)
		require.InDelta(t, 0.3, result[2].Position.SupplyShare, 0.0001)
	})

	t.Run("should return empty array when token has no holders", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		tokenExternalAddr := "0:nonexistent:token"

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("should respect limit parameter with content token", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator456"
		creatorBlockchainAddr := "0x5555555555555555555555555555555555555555"
		tokenContractAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		tokenExternalAddr := "0:creator456:token2"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000002"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator2", "Creator Two", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TK2", TokenTypePost, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 1.0)
		helperUpdateTokenBondingCurveMigrated(t, ctx, db, tokenExternalAddr, true)

		for i := 1; i <= 10; i++ {
			holderMasterPubkey := fmt.Sprintf("holder%d", i)
			holderExternalAddr := fmt.Sprintf("holder%d", i)
			holderBlockchainAddr := fmt.Sprintf("0x%040d", i)
			helperInsertTestUser(t, ctx, db, holderMasterPubkey, fmt.Sprintf("holder%d", i), fmt.Sprintf("Holder %d", i), holderBlockchainAddr, false, PlatformGroupIonConnect)
			helperInsertUserTokenPosition(t, ctx, db, holderMasterPubkey, tokenContractAddr, tokenExternalAddr, holderExternalAddr, "1000000000000000000", 1.0, 1.0)

			userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
			err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: float64(11 - i), Member: holderExternalAddr}).Err()
			require.NoError(t, err)

			userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
			err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: float64(11 - i), Member: holderBlockchainAddr}).Err()
			require.NoError(t, err)
		}

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 10, len(result))

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "holder1", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "10000000000000000000", result[0].Position.Amount)
		require.Equal(t, 10.0, result[0].Position.AmountUSD)
		require.InDelta(t, 1.0, result[0].Position.SupplyShare, 0.0001)

		require.Equal(t, uint64(2), result[1].Position.Rank)
		require.Equal(t, "holder2", strVal(result[1].Position.Holder.Username))

		require.Equal(t, uint64(10), result[9].Position.Rank)
		require.Equal(t, "holder10", strVal(result[9].Position.Holder.Username))
	})

	t.Run("should handle holders without user records", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator789"
		creatorBlockchainAddr := "0x6666666666666666666666666666666666666666"
		tokenContractAddr := "0xcccccccccccccccccccccccccccccccccccccccc"
		tokenExternalAddr := "0:creator789:token3"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000003"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator3", "Creator Three", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TK3", TokenTypePost, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 1.5)
		helperUpdateTokenBondingCurveMigrated(t, ctx, db, tokenExternalAddr, true)

		unknownHolderMasterPubkey := "unknown_holder"
		unknownHolderExternalAddr := "unknown_holder"
		unknownHolderBlockchainAddr := "0x7777777777777777777777777777777777777777"

		helperInsertUserTokenPosition(t, ctx, db, unknownHolderMasterPubkey, tokenContractAddr, tokenExternalAddr, unknownHolderExternalAddr, "3000000000000000000", 1.5, 4.5)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 3.0, Member: unknownHolderExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 3.0, Member: unknownHolderBlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 1, len(result))

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Nil(t, result[0].Position.Holder.Username)
		require.Nil(t, result[0].Position.Holder.Display)
		require.Nil(t, result[0].Position.Holder.Verified)
		require.Equal(t, unknownHolderMasterPubkey, result[0].Position.Holder.Addresses.Twitter)
		require.NotEmpty(t, result[0].Position.Holder.Addresses.Blockchain)
		require.Empty(t, result[0].Position.Holder.Addresses.IonConnect)
		require.Equal(t, "3000000000000000000", result[0].Position.Amount)
		require.InDelta(t, 4.5, result[0].Position.AmountUSD, 0.0001)
		require.InDelta(t, 0.3, result[0].Position.SupplyShare, 0.0001)

		require.Equal(t, "creator3", strVal(result[0].Creator.Username))
		require.Equal(t, "Creator Three", strVal(result[0].Creator.Display))
		require.False(t, *result[0].Creator.Verified)
		require.Equal(t, creatorMasterPubkey, result[0].Creator.Addresses.IonConnect)
		require.Equal(t, creatorBlockchainAddr, result[0].Creator.Addresses.Blockchain)
	})

	t.Run("should handle X.com platform holders with burned", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "123456789"
		creatorBlockchainAddr := "0x8888888888888888888888888888888888888888"
		tokenContractAddr := "0xdddddddddddddddddddddddddddddddddddddddd"
		tokenExternalAddr := "xcom:123456789:token1"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000004"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "xcom_creator", "X Creator", creatorBlockchainAddr, true, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "XTK", TokenTypePost, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 3.0)
		helperUpdateTokenBondingCurveMigrated(t, ctx, db, tokenExternalAddr, true)

		holderMasterPubkey := "987654321"
		holderExternalAddr := "987654321"
		holderBlockchainAddr := "0x9999999999999999999999999999999999999999"

		helperInsertTestUser(t, ctx, db, holderMasterPubkey, "xcom_holder", "X Holder", holderBlockchainAddr, false, PlatformGroupXCom)
		helperInsertUserTokenPosition(t, ctx, db, holderMasterPubkey, tokenContractAddr, tokenExternalAddr, holderExternalAddr, "7000000000000000000", 3.0, 21.0)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 7.0, Member: holderExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 7.0, Member: holderBlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 2, len(result))

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "xcom_holder", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "X Holder", strVal(result[0].Position.Holder.Display))
		require.False(t, *result[0].Position.Holder.Verified)
		require.NotNil(t, result[0].Position.Holder.Avatar)
		require.Equal(t, holderMasterPubkey, result[0].Position.Holder.Addresses.Twitter)
		require.Empty(t, result[0].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holderBlockchainAddr, result[0].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "7000000000000000000", result[0].Position.Amount)
		require.InDelta(t, 21.0, result[0].Position.AmountUSD, 0.0001)
		require.InDelta(t, 0.7, result[0].Position.SupplyShare, 0.0001)

		require.Equal(t, "xcom_creator", strVal(result[0].Creator.Username))
		require.Equal(t, "X Creator", strVal(result[0].Creator.Display))
		require.True(t, *result[0].Creator.Verified)
		require.Equal(t, creatorMasterPubkey, result[0].Creator.Addresses.Twitter)
		require.Empty(t, result[0].Creator.Addresses.IonConnect)
		require.Equal(t, creatorBlockchainAddr, result[0].Creator.Addresses.Blockchain)

		require.Equal(t, uint64(0), result[1].Position.Rank)
		require.Equal(t, "Burned", strVal(result[1].Position.Holder.Display))
		require.NotNil(t, result[1].Position.Holder.Avatar)
		require.Equal(t, ta.cfg.BondingCurve.BurnAddress, result[1].Position.Holder.Addresses.Blockchain)
	})

	t.Run("should calculate correct USD values", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator_usd"
		creatorBlockchainAddr := "0xaaaa000000000000000000000000000000000000"
		tokenContractAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		tokenExternalAddr := "0:creator_usd:token_usd"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000005"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator_usd", "Creator USD", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TUSD", TokenTypePost, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 2.0)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 5.0)
		helperUpdateTokenBondingCurveMigrated(t, ctx, db, tokenExternalAddr, true)

		holderMasterPubkey := "holder_usd"
		holderExternalAddr := "holder_usd"
		holderBlockchainAddr := "0xbbbb000000000000000000000000000000000000"

		helperInsertTestUser(t, ctx, db, holderMasterPubkey, "holder_usd", "Holder USD", holderBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, holderMasterPubkey, tokenContractAddr, tokenExternalAddr, holderExternalAddr, "4500000000000000000", 5.0, 22.5)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 4.5, Member: holderExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 4.5, Member: holderBlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 1, len(result))

		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "holder_usd", strVal(result[0].Position.Holder.Username))
		require.Equal(t, "Holder USD", strVal(result[0].Position.Holder.Display))
		require.False(t, *result[0].Position.Holder.Verified)
		require.NotNil(t, result[0].Position.Holder.Avatar)
		require.Equal(t, holderMasterPubkey, result[0].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holderBlockchainAddr, result[0].Position.Holder.Addresses.Blockchain)
		require.Empty(t, result[0].Position.Holder.Addresses.Twitter)
		require.Equal(t, "4500000000000000000", result[0].Position.Amount)
		require.InDelta(t, 22.5, result[0].Position.AmountUSD, 0.0001)
		require.InDelta(t, 0.45, result[0].Position.SupplyShare, 0.0001)

		require.Equal(t, "creator_usd", strVal(result[0].Creator.Username))
		require.Equal(t, "Creator USD", strVal(result[0].Creator.Display))
		require.False(t, *result[0].Creator.Verified)
		require.Equal(t, creatorMasterPubkey, result[0].Creator.Addresses.IonConnect)
		require.Equal(t, creatorBlockchainAddr, result[0].Creator.Addresses.Blockchain)
		require.Empty(t, result[0].Creator.Addresses.Twitter)
	})

	t.Run("should assign unique ranks when holders come from both ionConnect and blockchain rankings", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		bondingGoal, _ := new(big.Int).SetString("1000000000000000000000", 10)
		soldTokens, _ := new(big.Int).SetString("500000000000000000000", 10)
		config := &bondingcurvefixture.MockBackendConfig{
			BuyPrice:          big.NewInt(950000000000000000),
			SellPrice:         big.NewInt(1050000000000000000),
			SoldTokens:        soldTokens,
			TokensRaised:      big.NewInt(0),
			StartPrice:        big.NewInt(100000000000000000),
			EndPrice:          big.NewInt(200000000000000000),
			BondingTokensGoal: bondingGoal,
			CurrentPrice:      big.NewInt(150000000000000000),
			Migrated:          false,
		}
		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, config)
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator_rank"
		creatorBlockchainAddr := "0x1111000000000000000000000000000000000000"
		tokenContractAddr := "0xaaaa111111111111111111111111111111111111"
		tokenExternalAddr := "0:creator_rank:token_rank"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000099"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator_rank", "Creator Rank", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "RANK", TokenTypeProfile, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 2.0)

		holder1MasterPubkey := "holder_rank1"
		holder1ExternalAddr := "holder_rank1"
		holder1BlockchainAddr := "0x2222000000000000000000000000000000000000"
		holder2MasterPubkey := "holder_rank2"
		holder2ExternalAddr := "holder_rank2"
		holder2BlockchainAddr := "0x3333000000000000000000000000000000000000"
		holder3BlockchainAddr := "0x4444000000000000000000000000000000000000"
		holder4BlockchainAddr := "0x5555000000000000000000000000000000000000"

		helperInsertTestUser(t, ctx, db, holder1MasterPubkey, "holder_rank1", "Holder Rank 1", holder1BlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, holder2MasterPubkey, "holder_rank2", "Holder Rank 2", holder2BlockchainAddr, false, PlatformGroupIonConnect)

		helperInsertUserTokenPosition(t, ctx, db, holder1MasterPubkey, tokenContractAddr, tokenExternalAddr, holder1ExternalAddr, "40000000000000000000", 2.0, 80.0)
		helperInsertUserTokenPosition(t, ctx, db, holder2MasterPubkey, tokenContractAddr, tokenExternalAddr, holder2ExternalAddr, "30000000000000000000", 2.0, 60.0)
		helperInsertUserPosition(t, ctx, db, holder3BlockchainAddr, tokenContractAddr, tokenExternalAddr, "", "25000000000000000000")
		helperInsertUserPosition(t, ctx, db, holder4BlockchainAddr, tokenContractAddr, tokenExternalAddr, "", "20000000000000000000")

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 40.0, Member: holder1ExternalAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 30.0, Member: holder2ExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 40.0, Member: holder1BlockchainAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 30.0, Member: holder2BlockchainAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 25.0, Member: holder3BlockchainAddr}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 20.0, Member: holder4BlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 10)
		require.NoError(t, err)
		require.Equal(t, 6, len(result))

		require.Equal(t, uint64(0), result[0].Position.Rank)
		require.Equal(t, "Bonding Curve", strVal(result[0].Position.Holder.Display))

		require.Equal(t, uint64(0), result[1].Position.Rank)
		require.Equal(t, "Burned", strVal(result[1].Position.Holder.Display))

		require.Equal(t, uint64(1), result[2].Position.Rank)
		require.Equal(t, "holder_rank1", strVal(result[2].Position.Holder.Username))
		require.Equal(t, "Holder Rank 1", strVal(result[2].Position.Holder.Display))
		require.Equal(t, holder1MasterPubkey, result[2].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder1BlockchainAddr, result[2].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "40000000000000000000", result[2].Position.Amount)

		require.Equal(t, uint64(2), result[3].Position.Rank)
		require.Equal(t, "holder_rank2", strVal(result[3].Position.Holder.Username))
		require.Equal(t, "Holder Rank 2", strVal(result[3].Position.Holder.Display))
		require.Equal(t, holder2MasterPubkey, result[3].Position.Holder.Addresses.IonConnect)
		require.Equal(t, holder2BlockchainAddr, result[3].Position.Holder.Addresses.Blockchain)
		require.Equal(t, "30000000000000000000", result[3].Position.Amount)

		require.Equal(t, uint64(3), result[4].Position.Rank)
		require.Equal(t, holder3BlockchainAddr, result[4].Position.Holder.Addresses.Blockchain)
		require.Empty(t, result[4].Position.Holder.Addresses.IonConnect)
		require.Nil(t, result[4].Position.Holder.Username)
		require.Equal(t, "25000000000000000000", result[4].Position.Amount)

		require.Equal(t, uint64(4), result[5].Position.Rank)
		require.Equal(t, holder4BlockchainAddr, result[5].Position.Holder.Addresses.Blockchain)
		require.Empty(t, result[5].Position.Holder.Addresses.IonConnect)
		require.Nil(t, result[5].Position.Holder.Username)
		require.Equal(t, "20000000000000000000", result[5].Position.Amount)
	})

	t.Run("should respect limit=5 with bonding curve and burned", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		bondingGoal, _ := new(big.Int).SetString("1000000000000000000000", 10)
		soldTokens, _ := new(big.Int).SetString("500000000000000000000", 10)
		config := &bondingcurvefixture.MockBackendConfig{
			BuyPrice:          big.NewInt(950000000000000000),
			SellPrice:         big.NewInt(1050000000000000000),
			SoldTokens:        soldTokens,
			TokensRaised:      big.NewInt(0),
			StartPrice:        big.NewInt(100000000000000000),
			EndPrice:          big.NewInt(200000000000000000),
			BondingTokensGoal: bondingGoal,
			CurrentPrice:      big.NewInt(150000000000000000),
			Migrated:          false,
		}
		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, config)
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator_limit"
		creatorBlockchainAddr := "0x1111222222222222222222222222222222222222"
		tokenContractAddr := "0xaaaa222222222222222222222222222222222222"
		tokenExternalAddr := "0:creator_limit:token_limit"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000088"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator_limit", "Creator Limit", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "LIMIT", TokenTypeProfile, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 2.0)

		for i := 1; i <= 10; i++ {
			holderMasterPubkey := fmt.Sprintf("holder_limit_%d", i)
			holderExternalAddr := fmt.Sprintf("holder_limit_%d", i)
			holderBlockchainAddr := fmt.Sprintf("0x%040d", 1000+i)
			helperInsertTestUser(t, ctx, db, holderMasterPubkey, fmt.Sprintf("holder_limit_%d", i), fmt.Sprintf("Holder Limit %d", i), holderBlockchainAddr, false, PlatformGroupIonConnect)
			helperInsertUserTokenPosition(t, ctx, db, holderMasterPubkey, tokenContractAddr, tokenExternalAddr, holderExternalAddr, fmt.Sprintf("%d000000000000000000", 11-i), 2.0, float64((11-i)*2))

			userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
			err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: float64(11 - i), Member: holderExternalAddr}).Err()
			require.NoError(t, err)

			userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
			err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: float64(11 - i), Member: holderBlockchainAddr}).Err()
			require.NoError(t, err)
		}

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 5)
		require.NoError(t, err)
		require.Equal(t, 5, len(result), "Should return exactly 5 holders when limit=5")

		require.Equal(t, uint64(0), result[0].Position.Rank, "First should be bonding curve with rank 0")
		require.Equal(t, "Bonding Curve", strVal(result[0].Position.Holder.Display))

		require.Equal(t, uint64(0), result[1].Position.Rank, "Second should be burned with rank 0")
		require.Equal(t, "Burned", strVal(result[1].Position.Holder.Display))

		require.Equal(t, uint64(1), result[2].Position.Rank, "Third should be holder with rank 1")
		require.Equal(t, "holder_limit_1", strVal(result[2].Position.Holder.Username))

		require.Equal(t, uint64(2), result[3].Position.Rank, "Fourth should be holder with rank 2")
		require.Equal(t, "holder_limit_2", strVal(result[3].Position.Holder.Username))

		require.Equal(t, uint64(3), result[4].Position.Rank, "Fifth should be holder with rank 3")
		require.Equal(t, "holder_limit_3", strVal(result[4].Position.Holder.Username))
	})

	t.Run("should respect limit=1 returning only bonding curve", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		bondingGoal, _ := new(big.Int).SetString("1000000000000000000000", 10)
		soldTokens, _ := new(big.Int).SetString("500000000000000000000", 10)
		config := &bondingcurvefixture.MockBackendConfig{
			BuyPrice:          big.NewInt(950000000000000000),
			SellPrice:         big.NewInt(1050000000000000000),
			SoldTokens:        soldTokens,
			TokensRaised:      big.NewInt(0),
			StartPrice:        big.NewInt(100000000000000000),
			EndPrice:          big.NewInt(200000000000000000),
			BondingTokensGoal: bondingGoal,
			CurrentPrice:      big.NewInt(150000000000000000),
			Migrated:          false,
		}
		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, config)
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		creatorMasterPubkey := "creator_limit1"
		creatorBlockchainAddr := "0x1111333333333333333333333333333333333333"
		tokenContractAddr := "0xaaaa333333333333333333333333333333333333"
		tokenExternalAddr := "0:creator_limit1:token_limit1"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000077"

		helperInsertTestUser(t, ctx, db, creatorMasterPubkey, "creator_limit1", "Creator Limit1", creatorBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "LIM1", TokenTypeProfile, creatorMasterPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, 2.0)

		holderMasterPubkey := "holder_limit1_1"
		holderExternalAddr := "holder_limit1_1"
		holderBlockchainAddr := "0x2222333333333333333333333333333333333333"
		helperInsertTestUser(t, ctx, db, holderMasterPubkey, "holder_limit1_1", "Holder Limit1 1", holderBlockchainAddr, false, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, holderMasterPubkey, tokenContractAddr, tokenExternalAddr, holderExternalAddr, "50000000000000000000", 2.0, 100.0)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 50.0, Member: holderExternalAddr}).Err()
		require.NoError(t, err)

		userPositionKeyBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyBlockchain, redis.Z{Score: 50.0, Member: holderBlockchainAddr}).Err()
		require.NoError(t, err)

		result, err := ta.GetTopHolders(ctx, tokenExternalAddr, 1)
		require.NoError(t, err)
		require.Equal(t, 1, len(result), "Should return exactly 1 holder when limit=1")

		require.Equal(t, uint64(0), result[0].Position.Rank)
		require.Equal(t, "Bonding Curve", strVal(result[0].Position.Holder.Display))
	})
}

func helperUpdateTokenBondingCurveMigrated(t *testing.T, ctx context.Context, db *storage.DB, externalAddress string, migrated bool) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `UPDATE tokens SET bonding_curve_migrated = $1 WHERE external_address = $2`, migrated, externalAddress)
	require.NoError(t, err)
}
