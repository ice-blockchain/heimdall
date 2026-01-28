// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestUserBalanceNotifier(t *testing.T) {
	t.Run("handles user balance update via handleUserBalanceUpdate", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:balance_test_token:"
		contractAddr := "0x1111222233334444555566667777888899990000"
		userExternalAddr := "0:balance_test_user:"
		userBlockchainAddr := "0x0000000000000000000000000000000000000001"

		helperInsertTestUser(t, ctx, db, userExternalAddr, "balance_test_user", "Balance Test User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "BTEST", "profile", userExternalAddr,
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		_, err := storage.Exec(ctx, db, `
			INSERT INTO user_token_positions (
				user_blockchain_address, user_external_address, 
				contract_address, external_address, amount, updated_at
			) VALUES ($1, $2, $3, $4, $5, NOW())`,
			userBlockchainAddr, userExternalAddr,
			contractAddr, tokenExternalAddr, "1000000000000000000") // 1 token
		require.NoError(t, err)

		payload := fmt.Sprintf(`{
			"user_blockchain_address": "%s",
			"user_external_address": "%s",
			"contract_address": "%s",
			"external_address": "%s",
			"amount": "10000000000000000000",
			"updated_at": 1234567890
		}`, userBlockchainAddr, userExternalAddr, contractAddr, tokenExternalAddr)

		err = ta.handleUserBalanceUpdate(ctx, payload)
		require.NoError(t, err)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		score, err := ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 10.0, score, 0.001, "User position should be 10 tokens")

		userPositionKeyByBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
		scoreByBlockchain, err := ta.processedDataDB.ZScore(ctx, userPositionKeyByBlockchain, userBlockchainAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 10.0, scoreByBlockchain, 0.001, "User position by blockchain address should be 10 tokens")
	})

	t.Run("removes user position when balance is zero", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:balance_zero_token:"
		contractAddr := "0x2222333344445555666677778888999900001111"
		userExternalAddr := "0:balance_zero_user:"
		userBlockchainAddr := "0x0000000000000000000000000000000000000002"

		helperInsertTestUser(t, ctx, db, userExternalAddr, "balance_zero_user", "Zero Balance User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "ZTEST", "profile", userExternalAddr,
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		userPositionKeyByBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)

		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{
			Score:  50.0,
			Member: userExternalAddr,
		}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.ZAdd(ctx, userPositionKeyByBlockchain, redis.Z{
			Score:  50.0,
			Member: userBlockchainAddr,
		}).Err()
		require.NoError(t, err)

		payload := fmt.Sprintf(`{
			"user_blockchain_address": "%s",
			"user_external_address": "%s",
			"contract_address": "%s",
			"external_address": "%s",
			"amount": "0",
			"updated_at": 1234567890
		}`, userBlockchainAddr, userExternalAddr, contractAddr, tokenExternalAddr)

		err = ta.handleUserBalanceUpdate(ctx, payload)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "User position should be removed when balance is zero")

		_, err = ta.processedDataDB.ZScore(ctx, userPositionKeyByBlockchain, userBlockchainAddr).Result()
		require.Equal(t, redis.Nil, err, "User position by blockchain address should be removed when balance is zero")
	})

	t.Run("handles multiple users for same token", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:multi_user_token:"
		contractAddr := "0x3333444455556666777788889999000011112222"
		user1ExternalAddr := "0:multi_user_1:"
		user1BlockchainAddr := "0x0000000000000000000000000000000000000003"
		user2ExternalAddr := "0:multi_user_2:"
		user2BlockchainAddr := "0x0000000000000000000000000000000000000004"

		helperInsertTestUser(t, ctx, db, user1ExternalAddr, "multi_user_1", "Multi User 1", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, user2ExternalAddr, "multi_user_2", "Multi User 2", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "MTEST", "profile", user1ExternalAddr,
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		payload1 := fmt.Sprintf(`{
			"user_blockchain_address": "%s",
			"user_external_address": "%s",
			"contract_address": "%s",
			"external_address": "%s",
			"amount": "25000000000000000000",
			"updated_at": 1234567890
		}`, user1BlockchainAddr, user1ExternalAddr, contractAddr, tokenExternalAddr)

		err := ta.handleUserBalanceUpdate(ctx, payload1)
		require.NoError(t, err)

		payload2 := fmt.Sprintf(`{
			"user_blockchain_address": "%s",
			"user_external_address": "%s",
			"contract_address": "%s",
			"external_address": "%s",
			"amount": "15000000000000000000",
			"updated_at": 1234567891
		}`, user2BlockchainAddr, user2ExternalAddr, contractAddr, tokenExternalAddr)

		err = ta.handleUserBalanceUpdate(ctx, payload2)
		require.NoError(t, err)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)

		score1, err := ta.processedDataDB.ZScore(ctx, userPositionKey, user1ExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 25.0, score1, 0.001, "User 1 should have 25 tokens")

		score2, err := ta.processedDataDB.ZScore(ctx, userPositionKey, user2ExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 15.0, score2, 0.001, "User 2 should have 15 tokens")

		count, err := ta.processedDataDB.ZCard(ctx, userPositionKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(2), count, "Should have 2 users in the position set")

		userPositionKeyByBlockchain := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)

		score1Blockchain, err := ta.processedDataDB.ZScore(ctx, userPositionKeyByBlockchain, user1BlockchainAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 25.0, score1Blockchain, 0.001, "User 1 should have 25 tokens by blockchain address")

		score2Blockchain, err := ta.processedDataDB.ZScore(ctx, userPositionKeyByBlockchain, user2BlockchainAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 15.0, score2Blockchain, 0.001, "User 2 should have 15 tokens by blockchain address")

		countBlockchain, err := ta.processedDataDB.ZCard(ctx, userPositionKeyByBlockchain).Result()
		require.NoError(t, err)
		require.Equal(t, int64(2), countBlockchain, "Should have 2 users in the position set by blockchain address")
	})

	t.Run("returns error for invalid amount", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		payload := `{
			"user_blockchain_address": "0x0000000000000000000000000000000000000001",
			"user_external_address": "0:test:",
			"contract_address": "0x1234567890123456789012345678901234567890",
			"external_address": "0:test_token:",
			"amount": "invalid_number",
			"updated_at": 1234567890
		}`

		err := ta.handleUserBalanceUpdate(ctx, payload)
		require.Error(t, err)
	})
}
