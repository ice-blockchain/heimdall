// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestBalanceUpdateJob_WithDummyBalance(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := fixture.SetupMockedBondingCurveBackend(t, fixture.DefaultMockBackendConfig())
	mockBC := fixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()

	userBlockchainAddr := "0x1234567890123456789012345678901234567890"
	userExternalAddr := "test_user_dummy"
	contractAddr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	tokenExternalAddr := "test_token_dummy"

	helperInsertTestUser(t, ctx, db, userExternalAddr, "test_user", "Test User", userBlockchainAddr, false, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "TEST", "profile", userExternalAddr, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

	dummyBalance := "3500000000000000000" // 3.5 tokens
	err := ta.(*tokenAnalytics).balanceUpdateQueue.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       contractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       "0xdummy123",
		DummyBalance:          &dummyBalance,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta.(*tokenAnalytics), 10*time.Second)

	type position struct {
		Amount string `db:"amount"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount FROM user_token_positions 
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, userBlockchainAddr, contractAddr)
	require.NoError(t, err)
	require.Equal(t, dummyBalance, pos.Amount, "Should use dummy balance, not RPC")

	userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
	score, err := ta.(*tokenAnalytics).processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
	require.NoError(t, err)
	require.InDelta(t, 3.5, score, 0.0001, "Redis should have dummy balance")
}

func TestBalanceUpdateJob_WithRPC(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := fixture.SetupMockedBondingCurveBackend(t, fixture.DefaultMockBackendConfig())
	mockBackend.SetBalanceOfResponse(big.NewInt(5000000000000000000)) // 5 tokens
	mockBC := fixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()

	userBlockchainAddr := "0x1234567890123456789012345678901234567890"
	userExternalAddr := "0:testuser1:"
	tokenContractAddr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	tokenExternalAddr := "0:testuser1:testtoken1"
	txHash := "0xdeadbeef1"

	helperInsertTestUser(t, ctx, db, userExternalAddr, "testuser1", "Test User 1", userBlockchainAddr, false, "ionconnect")
	helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TEST1", "profile", userExternalAddr, "1000000000000000000000000000", 0, 0, 0, "ionconnect")
	helperInsertUserPosition(t, ctx, db, userBlockchainAddr, tokenContractAddr, tokenExternalAddr, userExternalAddr, "0")

	err := ta.(*tokenAnalytics).balanceUpdateQueue.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       tokenContractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       txHash,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta.(*tokenAnalytics), 10*time.Second)

	type position struct {
		Amount string `db:"amount"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount FROM user_token_positions
		WHERE LOWER(user_blockchain_address) = LOWER($1) AND LOWER(contract_address) = LOWER($2)
	`, userBlockchainAddr, tokenContractAddr)
	require.NoError(t, err)
	require.Equal(t, "5000000000000000000", pos.Amount, "Balance should be updated to 5 tokens")

	t.Logf("Checking Redis for key=%s, member=%s", keyUserPositionOfToken(tokenExternalAddr), userExternalAddr)
	score, err := ta.(*tokenAnalytics).processedDataDB.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddr), userExternalAddr).Result()
	require.NoError(t, err, "Redis entry should exist for user position")
	require.InDelta(t, 5.0, score, 0.01, "Redis score should be 5.0")
}

func TestBalanceUpdateJob_ZeroBalance(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := fixture.SetupMockedBondingCurveBackend(t, fixture.DefaultMockBackendConfig())
	mockBackend.SetBalanceOfResponse(big.NewInt(0)) // 0 tokens
	mockBC := fixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()

	userBlockchainAddr := "0x2345678901234567890123456789012345678901"
	userExternalAddr := "0:testuser2:"
	tokenContractAddr := "0xbcdefabcdefabcdefabcdefabcdefabcdefabcde"
	tokenExternalAddr := "0:testuser2:testtoken2"
	txHash := "0xdeadbeef2"

	helperInsertTestUser(t, ctx, db, userExternalAddr, "testuser2", "Test User 2", userBlockchainAddr, false, "ionconnect")
	helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TEST2", "profile", userExternalAddr, "1000000000000000000000000000", 0, 0, 0, "ionconnect")

	helperInsertUserPosition(t, ctx, db, userBlockchainAddr, tokenContractAddr, tokenExternalAddr, userExternalAddr, "1000000000000000000")

	err := ta.(*tokenAnalytics).processedDataDB.ZAdd(ctx, keyUserPositionOfToken(tokenExternalAddr), redis.Z{
		Score:  1.0,
		Member: userExternalAddr,
	}).Err()
	require.NoError(t, err)

	err = ta.(*tokenAnalytics).balanceUpdateQueue.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       tokenContractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       txHash,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta.(*tokenAnalytics), 10*time.Second)

	type position struct {
		Amount string `db:"amount"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount FROM user_token_positions
		WHERE LOWER(user_blockchain_address) = LOWER($1) AND LOWER(contract_address) = LOWER($2)
	`, userBlockchainAddr, tokenContractAddr)
	require.NoError(t, err)
	require.Equal(t, "0", pos.Amount, "Balance should be updated to 0")

	_, err = ta.(*tokenAnalytics).processedDataDB.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddr), userExternalAddr).Result()
	require.Error(t, err, "Entry should be removed from Redis when balance is 0")
}

func helperInsertUserPosition(t testing.TB, ctx context.Context, db *storage.DB, userBlockchainAddr, contractAddr, tokenExternalAddr, userExternalAddr, amount string) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		INSERT INTO user_token_positions (
			user_blockchain_address, contract_address, external_address, user_external_address,
			amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, 0, 0, 0, NOW())
	`, userBlockchainAddr, contractAddr, tokenExternalAddr, userExternalAddr, amount)
	require.NoError(t, err)
}
