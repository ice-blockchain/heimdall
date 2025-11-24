// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func Test_buildTopHolderPositions(t *testing.T) {
	t.Skip("skipping until we move tests to dedicated pr")
	t.Parallel()

	contractAddr := "0xcontract123"
	t.Run("should build positions with complete data", func(t *testing.T) {
		t.Parallel()

		rankings := []redis.Z{
			{Score: 1.0005, Member: "0:pubkey1:"},  // 1.0005 tokens (user ion_connect format)
			{Score: 0.50025, Member: "0:pubkey2:"}, // 0.50025 tokens
			{Score: 0.1, Member: "0:pubkey3:"},     // 0.1 tokens
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
				HolderIonConnect:    "0:pubkey1:",
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
				HolderIonConnect:    "0:pubkey2:",
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
				HolderIonConnect:    "0:pubkey3:",
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rows)
		require.NoError(t, err)
		require.Len(t, result, 3)
		require.Equal(t, uint64(1), result[0].Position.Rank)
		require.Equal(t, "holder1", result[0].Position.Holder.Username)
		require.Equal(t, "pubkey1", result[0].Position.Holder.MasterPubkey)
		require.Equal(t, uint64(1), result[0].Position.Amount)   // 1.0005 tokens (rounded to uint64)
		require.Equal(t, 1.50075, result[0].Position.AmountUSD)  // 1.0005 tokens * 1.5 USD
		require.Equal(t, 1.0005, result[0].Position.SupplyShare) // 1.0005 / 100 * 100
		require.Equal(t, "0:pubkey1:", result[0].Position.Holder.Addresses.IonConnect)
		require.True(t, result[0].Position.Holder.Verified)

		require.Equal(t, "creator_user", result[0].Creator.Username)
		require.Equal(t, "Creator Name", result[0].Creator.Display)
		require.Equal(t, "0:creator_pubkey:", result[0].Creator.Addresses.IonConnect)
		require.True(t, result[0].Creator.Verified)

		require.Equal(t, uint64(2), result[1].Position.Rank)
		require.Equal(t, "holder2", result[1].Position.Holder.Username)
		require.Equal(t, uint64(0), result[1].Position.Amount)    // 0.50025 tokens (rounded to uint64 = 0)
		require.Equal(t, 0.750375, result[1].Position.AmountUSD)  // 0.50025 tokens * 1.5 USD
		require.Equal(t, 0.50025, result[1].Position.SupplyShare) // 0.50025 / 100 * 100
		require.False(t, result[1].Position.Holder.Verified)

		require.Equal(t, uint64(3), result[2].Position.Rank)
		require.Equal(t, "holder3", result[2].Position.Holder.Username)
		require.Equal(t, uint64(0), result[2].Position.Amount)              // 0.1 tokens (rounded to uint64 = 0)
		require.Equal(t, 0.15000000000000002, result[2].Position.AmountUSD) // 0.1 tokens * 1.5 USD
		require.Equal(t, 0.1, result[2].Position.SupplyShare)               // 0.1 / 100 * 100
		require.Empty(t, result[2].Position.Holder.Avatar)
	})

	t.Run("should handle empty rankings", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{}
		rows := []*holderWithTokenData{}
		result, err := buildTopHolderPositions(contractAddr, rankings, rows)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("should skip holder when data not found in rows", func(t *testing.T) {
		t.Parallel()
		rankings := []redis.Z{
			{Score: 1.0, Member: "0:pubkey1:"},
			{Score: 0.5, Member: "0:pubkey_missing:"},
			{Score: 0.1, Member: "0:pubkey3:"},
		}
		rows := []*holderWithTokenData{
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:  "pubkey1",
				HolderUsername:      "user1",
				HolderIonConnect:    "0:pubkey1:",
			},
			{
				CreatorMasterPubkey: "creator_pubkey",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)).String(),
				HolderMasterPubkey:  "pubkey3",
				HolderUsername:      "user3",
				HolderIonConnect:    "0:pubkey3:",
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rows)
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.Equal(t, "user1", result[0].Position.Holder.Username)
		require.Equal(t, "user3", result[1].Position.Holder.Username)
	})

	t.Run("should calculate correct supply share percentages", func(t *testing.T) {
		t.Parallel()

		totalSupply := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 tokens
		rankings := []redis.Z{
			{Score: 5.0, Member: "0:pubkey1:"}, // 5 tokens = 50%
			{Score: 3.0, Member: "0:pubkey2:"}, // 3 tokens = 30%
			{Score: 2.0, Member: "0:pubkey3:"}, // 2 tokens = 20%
		}
		rows := []*holderWithTokenData{
			{
				CreatorMasterPubkey: "creator",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         totalSupply.String(),
				HolderMasterPubkey:  "pubkey1",
				HolderUsername:      "user1",
				HolderIonConnect:    "0:pubkey1:",
			},
			{
				CreatorMasterPubkey: "creator",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         totalSupply.String(),
				HolderMasterPubkey:  "pubkey2",
				HolderUsername:      "user2",
				HolderIonConnect:    "0:pubkey2:",
			},
			{
				CreatorMasterPubkey: "creator",
				CreatorUsername:     "creator",
				PriceUSD:            1.0,
				TotalSupply:         totalSupply.String(),
				HolderMasterPubkey:  "pubkey3",
				HolderUsername:      "user3",
				HolderIonConnect:    "0:pubkey3:",
			},
		}

		result, err := buildTopHolderPositions(contractAddr, rankings, rows)
		require.NoError(t, err)

		require.Len(t, result, 3)
		require.Equal(t, 50.0, result[0].Position.SupplyShare)
		require.Equal(t, 30.0, result[1].Position.SupplyShare)
		require.Equal(t, 20.0, result[2].Position.SupplyShare)
	})
}

func TestGetTopHolders(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	tokenIonConnect := "30001:creator_master_pubkey:test_token"
	tokenContractAddr := "0xabcdef1234567890abcdef1234567890abcdef12"

	t.Run("returns_top_holders_successfully", func(t *testing.T) {
		t.Parallel()

		helperInsertTestUser(t, ctx, testDB, "creator_master_pubkey", "creator_user", "Creator Name", "0xcreator123", true)
		helperInsertTestUser(t, ctx, testDB, "holder1_pubkey", "holder1", "Holder One", "0xholder1addr", true)
		helperInsertTestUser(t, ctx, testDB, "holder2_pubkey", "holder2", "Holder Two", "0xholder2addr", false)
		helperInsertTestUser(t, ctx, testDB, "holder3_pubkey", "holder3", "Holder Three", "0xholder3addr", true)

		helperInsertTestToken(t, ctx, testDB, tokenContractAddr, tokenIonConnect, "TEST", "30001", "creator_master_pubkey",
			"100000000000000000000", 150.0, 1.5, 0)

		redisKey := keyUserPositionOfToken(tokenIonConnect)
		err := testRedis.ZAdd(ctx, redisKey, redis.Z{Score: 50.0, Member: "0:holder1_pubkey:"}).Err()
		require.NoError(t, err)
		err = testRedis.ZAdd(ctx, redisKey, redis.Z{Score: 30.0, Member: "0:holder2_pubkey:"}).Err()
		require.NoError(t, err)
		err = testRedis.ZAdd(ctx, redisKey, redis.Z{Score: 20.0, Member: "0:holder3_pubkey:"}).Err()
		require.NoError(t, err)

		ta := &tokenAnalytics{
			ingestedDataDB:  testDB,
			processedDataDB: testRedis,
		}

		result, err := ta.GetTopHolders(ctx, tokenIonConnect, 10)
		require.NoError(t, err)
		require.Len(t, result, 3)

		require.Equal(t, "holder1", result[0].Position.Holder.Username)
		require.Equal(t, "0:holder1_pubkey:", result[0].Position.Holder.IonConnect)
		require.Equal(t, uint64(50), result[0].Position.Amount) // 50 tokens (not wei)
		require.Equal(t, 75.0, result[0].Position.AmountUSD)    // 50 tokens * 1.5 price

		require.Equal(t, "holder2", result[1].Position.Holder.Username)
		require.Equal(t, uint64(30), result[1].Position.Amount) // 30 tokens

		require.Equal(t, "holder3", result[2].Position.Holder.Username)
		require.Equal(t, uint64(20), result[2].Position.Amount) // 20 tokens
	})

	t.Run("respects_limit_parameter", func(t *testing.T) {
		t.Parallel()

		helperInsertTestUser(t, ctx, testDB, "creator2_pubkey", "creator2", "Creator Two", "0xcreator2", true)
		helperInsertTestUser(t, ctx, testDB, "holder4_pubkey", "holder4", "Holder Four", "0xholder4", true)
		helperInsertTestUser(t, ctx, testDB, "holder5_pubkey", "holder5", "Holder Five", "0xholder5", false)
		helperInsertTestUser(t, ctx, testDB, "holder6_pubkey", "holder6", "Holder Six", "0xholder6", true)

		token2IonConnect := "30001:creator2_pubkey:token2"
		token2Addr := "0xabcdef1234567890abcdef1234567890abcdef22"
		helperInsertTestToken(t, ctx, testDB, token2Addr, token2IonConnect, "TT2", "30001", "creator2_pubkey",
			"100000000000000000000", 200.0, 2.0, 0)

		redisKey := keyUserPositionOfToken(token2IonConnect)
		err := testRedis.ZAdd(ctx, redisKey, redis.Z{Score: 100.0, Member: "0:holder4_pubkey:"}).Err()
		require.NoError(t, err)
		err = testRedis.ZAdd(ctx, redisKey, redis.Z{Score: 50.0, Member: "0:holder5_pubkey:"}).Err()
		require.NoError(t, err)
		err = testRedis.ZAdd(ctx, redisKey, redis.Z{Score: 25.0, Member: "0:holder6_pubkey:"}).Err()
		require.NoError(t, err)

		ta := &tokenAnalytics{
			ingestedDataDB:  testDB,
			processedDataDB: testRedis,
		}

		result, err := ta.GetTopHolders(ctx, token2IonConnect, 2)
		require.NoError(t, err)
		require.Len(t, result, 2)

		require.Equal(t, "holder4", result[0].Position.Holder.Username)
		require.Equal(t, "holder5", result[1].Position.Holder.Username)
	})

	t.Run("returns_empty_for_non_existent_token", func(t *testing.T) {
		t.Parallel()

		ta := &tokenAnalytics{
			ingestedDataDB:  testDB,
			processedDataDB: testRedis,
		}

		result, err := ta.GetTopHolders(ctx, "30001:nonexistent:token", 10)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("returns_empty_for_token_with_no_holders", func(t *testing.T) {
		t.Parallel()

		helperInsertTestUser(t, ctx, testDB, "creator3_pubkey", "creator3", "Creator Three", "0xcreator3", true)

		token3IonConnect := "30001:creator3_pubkey:token3"
		token3Addr := "0xabcdef1234567890abcdef1234567890abcdef33"
		helperInsertTestToken(t, ctx, testDB, token3Addr, token3IonConnect, "TT3", "30001", "creator3_pubkey",
			"100000000000000000000", 100.0, 1.0, 0)

		ta := &tokenAnalytics{
			ingestedDataDB:  testDB,
			processedDataDB: testRedis,
		}

		result, err := ta.GetTopHolders(ctx, token3IonConnect, 10)
		require.NoError(t, err)
		require.Empty(t, result)
	})
}
