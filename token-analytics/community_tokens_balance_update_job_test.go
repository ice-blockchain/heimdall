// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
	bondingcurvefixture "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve/fixture"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestBalanceUpdateJob_WithDummyBalance(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
	defer ta.Close()

	userBlockchainAddr := "0x1234567890123456789012345678901234567890"
	userExternalAddr := "test_user_dummy"
	contractAddr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	tokenExternalAddr := "test_token_dummy"

	helperInsertTestUser(t, ctx, db, userExternalAddr, "test_user", "Test User", userBlockchainAddr, false, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "TEST", "profile", userExternalAddr, "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

	pairID := "0x0000000000000000000000000000000000000000000000000000000000000001"
	baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
	helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)

	dummyBalance := "3500000000000000000" // 3.5 tokens
	err := ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       contractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       "0xdummy123",
		BlockNumber:           12345,
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             "profile",
		Platform:              PlatformGroupIonConnect,
		DummyBalance:          &dummyBalance,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

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
	score, err := ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
	require.NoError(t, err)
	require.InDelta(t, 3.5, score, 0.0001, "Redis should have dummy balance")
}

func TestBalanceUpdateJob_WithRPC(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBackend.SetBalanceOfResponse(big.NewInt(5000000000000000000)) // 5 tokens
	mockBackend.SetBondingCurveResponse(bondingcurve.BondingCurveBondingInfo{
		CurrentPrice:      big.NewInt(500000000000000000), // 0.5 base
		SoldTokens:        big.NewInt(int64(1e18)),
		BondingTokensGoal: big.NewInt(int64(5e18)),
		TokensRaised:      big.NewInt(int64(1e18)),
		EndPrice:          big.NewInt(int64(1e17)),
		StartPrice:        big.NewInt(int64(1e18)),
		Migrated:          false,
	})
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
	defer ta.Close()

	userBlockchainAddr := "0x1234567890123456789012345678901234567890"
	userExternalAddr := "0:testuser1:"
	tokenContractAddr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	tokenExternalAddr := "0:testuser1:testtoken1"
	txHash := "0xdeadbeef1"

	helperInsertTestUser(t, ctx, db, userExternalAddr, "testuser1", "Test User 1", userBlockchainAddr, false, "ionconnect")
	helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TEST1", "profile", userExternalAddr, "1000000000000000000000000000", 0, 0, 0, "ionconnect")
	helperInsertUserPosition(t, ctx, db, userBlockchainAddr, tokenContractAddr, tokenExternalAddr, userExternalAddr, "0")

	helperInsertBaseTokenPrice(t, ctx, db, "0x2c73996babf1a06c2c057177353293f7ca0907c8", "ION", 0.01)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, "0x0000000000000000000000000000000000000000000000000000000000000001", "0x2c73996babf1a06c2c057177353293f7ca0907c8")
	helperInsertUnprocessedSwap(t, ctx, db, tokenContractAddr, tokenExternalAddr, userBlockchainAddr,
		txHash, false, "1000000000000000000", "5000000000000000000", 0.10, "0")
	err := ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       tokenContractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       txHash,
		BlockNumber:           12345,
		PairID:                "0x0000000000000000000000000000000000000000000000000000000000000001",
		BaseToken:             "0x2c73996babf1a06c2c057177353293f7ca0907c8",
		TokenType:             "profile",
		Platform:              PlatformGroupIonConnect,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	type position struct {
		Amount           string  `db:"amount"`
		TotalInvestedUSD float64 `db:"total_invested_usd"`
		TotalRealizedUSD float64 `db:"total_realized_usd"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount, total_invested_usd, total_realized_usd FROM user_token_positions
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, strings.ToLower(userBlockchainAddr), strings.ToLower(tokenContractAddr))
	require.NoError(t, err)
	require.Equal(t, "5000000000000000000", pos.Amount, "Balance should be updated to 5 tokens")
	// invested = input_amount × basePriceUSD = (1e18 / 1e18) × 1.15 = 1.15
	// input_amount=1e18 (1 ION), basePriceUSD=ionPrice=1.15
	require.InDelta(t, 1.15, pos.TotalInvestedUSD, 0.0001, "Total invested USD should be input_amount * basePriceUSD (1 ION * 1.15)")
	require.Equal(t, float64(0), pos.TotalRealizedUSD, "Total realized USD should be 0 as it was buy")
	t.Logf("Checking Redis for key=%s, member=%s", keyUserPositionOfToken(tokenExternalAddr), userExternalAddr)
	score, err := ta.processedDataDB.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddr), userExternalAddr).Result()
	require.NoError(t, err, "Redis entry should exist for user position")
	require.InDelta(t, 5.0, score, 0.01, "Redis score should be 5.0")

	bcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, bcScore, "Global bonding curve progress should be updated")

	profileBcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressProfileSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, profileBcScore, "Profile bonding curve progress should be updated")

	_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomSetKey, tokenExternalAddr).Result()
	require.Equal(t, redis.Nil, err, "IonConnect token should NOT be in xcom-specific bonding curve set")
}

func TestBalanceUpdateJob_ZeroBalance(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBackend.SetBalanceOfResponse(big.NewInt(0)) // 0 tokens
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
	defer ta.Close()

	userBlockchainAddr := "0x2345678901234567890123456789012345678901"
	userExternalAddr := "0:testuser2:"
	tokenContractAddr := "0xbcdefabcdefabcdefabcdefabcdefabcdefabcde"
	tokenExternalAddr := "0:testuser2:testtoken2"
	txHash := "0xdeadbeef2"

	helperInsertTestUser(t, ctx, db, userExternalAddr, "testuser2", "Test User 2", userBlockchainAddr, false, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExternalAddr, "TEST2", "profile", userExternalAddr, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

	helperInsertUserPosition(t, ctx, db, userBlockchainAddr, tokenContractAddr, tokenExternalAddr, userExternalAddr, "1000000000000000000")

	err := ta.processedDataDB.ZAdd(ctx, keyUserPositionOfToken(tokenExternalAddr), redis.Z{
		Score:  1.0,
		Member: userExternalAddr,
	}).Err()
	require.NoError(t, err)

	helperInsertBaseTokenPrice(t, ctx, db, "0x2c73996babf1a06c2c057177353293f7ca0907c8", "ION", 0.01)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, "0x0000000000000000000000000000000000000000000000000000000000000002", "0x2c73996babf1a06c2c057177353293f7ca0907c8")

	err = ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       tokenContractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       txHash,
		BlockNumber:           12345,
		PairID:                "0x0000000000000000000000000000000000000000000000000000000000000002",
		BaseToken:             "0x2c73996babf1a06c2c057177353293f7ca0907c8",
		TokenType:             "profile",
		Platform:              PlatformGroupIonConnect,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	type position struct {
		Amount string `db:"amount"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount FROM user_token_positions
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, strings.ToLower(userBlockchainAddr), strings.ToLower(tokenContractAddr))
	require.NoError(t, err)
	require.Equal(t, "0", pos.Amount, "Balance should be updated to 0")

	_, err = ta.processedDataDB.ZScore(ctx, keyUserPositionOfToken(tokenExternalAddr), userExternalAddr).Result()
	require.Error(t, err, "Entry should be removed from Redis when balance is 0")
}

func TestBalanceUpdateJob_XcomPlatform(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
	defer ta.Close()

	userBlockchainAddr := "0xXCOMBALANCE000000000000000000000000001"
	userExternalAddr := "xcom_balance_user"
	contractAddr := "0xXCOMBALANCETOKEN00000000000000000001"
	tokenExternalAddr := "xcom_balance_token_123"
	pairID := "0xaaaa000000000000000000000000000000000000000000000000000000000001"
	baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

	helperInsertTestUser(t, ctx, db, "xcom_balance_creator", "xcom_bal_user", "XCom Balance User", userBlockchainAddr, false, PlatformGroupXCom)
	helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "XBAL", TokenTypePost, "xcom_balance_creator",
		"1000000000000000000000", 0, 0, 0, PlatformGroupXCom)

	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
	helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
	helperInsertUserPosition(t, ctx, db, userBlockchainAddr, contractAddr, tokenExternalAddr, userExternalAddr, "0")

	dummyBalance := "5000000000000000000" // 5 tokens
	err := ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddr,
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       contractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       "0xxcom_balance_test",
		BlockNumber:           12345,
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             TokenTypePost,
		Platform:              PlatformGroupXCom,
		DummyBalance:          &dummyBalance,
	})
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	type position struct {
		Amount           string  `db:"amount"`
		TotalInvestedUSD float64 `db:"total_invested_usd"`
		TotalRealizedUSD float64 `db:"total_realized_usd"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount, total_invested_usd, total_realized_usd FROM user_token_positions 
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, userBlockchainAddr, contractAddr)
	require.NoError(t, err)
	require.Equal(t, dummyBalance, pos.Amount, "Should use dummy balance")

	userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
	score, err := ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
	require.NoError(t, err)
	require.InDelta(t, 5.0, score, 0.0001, "Redis should have dummy balance")

	// Check bonding curve sets for xcom platform
	bcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, bcScore, "Global bonding curve progress should be updated")

	xcomBcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, xcomBcScore, "Xcom bonding curve progress should be updated")

	postBcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressPostSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, postBcScore, "Xcom post token should be in post-specific bonding curve set")

	anyPostBcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressAnyPostSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, anyPostBcScore, "Xcom post token should be in anyPost bonding curve set")

	combinedBcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomCombinedSetKey, tokenExternalAddr).Result()
	require.NoError(t, err)
	require.NotEqual(t, 0.0, combinedBcScore, "Xcom token should be in combined bonding curve set")
}

func TestBalanceUpdateJob_MultiAddressAggregateRedis(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := fixture.SetupMockedBondingCurveBackend(t, fixture.DefaultMockBackendConfig())
	mockBC := fixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()

	userExternalAddr := "0:multi_redis_user:"
	userID := "multi-redis-user-id"
	bscAddr1 := "0xMULTIREDIS_BSC_001"
	bscAddr2 := "0xMULTIREDIS_BSC_002"

	helperCreateUser(t, ctx, db, userID, "multi_redis_user", userExternalAddr, "multiredis", "Multi Redis User", "avatar.png", "ionconnect")
	helperAddUserBscAddress(t, ctx, db, userID, bscAddr1)
	helperAddUserBscAddress(t, ctx, db, userID, bscAddr2)

	contractAddr := "0xMULTIREDISTOKEN0000000000000000000001"
	tokenExternalAddr := "0:multi_redis_token:"
	pairID := "0xcccc000000000000000000000000000000000000000000000000000000000001"
	baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

	helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "MRT", "profile", "multi_redis_user",
		"1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
	helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)

	// First address has 3 tokens
	dummyBal1 := "3000000000000000000" // 3 tokens
	err := ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: strings.ToLower(bscAddr1),
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       contractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       "0xmulti_redis_tx1",
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             "profile",
		Platform:              PlatformGroupIonConnect,
		DummyBalance:          &dummyBal1,
	})
	require.NoError(t, err)
	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	// Second address has 7 tokens
	dummyBal2 := "7000000000000000000" // 7 tokens
	err = ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
		UserBlockchainAddress: strings.ToLower(bscAddr2),
		UserExternalAddress:   userExternalAddr,
		ContractAddress:       contractAddr,
		TokenExternalAddress:  tokenExternalAddr,
		TransactionHash:       "0xmulti_redis_tx2",
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             "profile",
		Platform:              PlatformGroupIonConnect,
		DummyBalance:          &dummyBal2,
	})
	require.NoError(t, err)
	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
	score, err := ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
	require.NoError(t, err)
	require.InDelta(t, 10.0, score, 0.01, "Primary Redis key should have AGGREGATE balance (3+7=10)")

	byBlockchainKey := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddr)
	score1, err := ta.processedDataDB.ZScore(ctx, byBlockchainKey, strings.ToLower(bscAddr1)).Result()
	require.NoError(t, err)
	require.InDelta(t, 3.0, score1, 0.01, "Secondary Redis key should have individual balance for addr1")

	score2, err := ta.processedDataDB.ZScore(ctx, byBlockchainKey, strings.ToLower(bscAddr2)).Result()
	require.NoError(t, err)
	require.InDelta(t, 7.0, score2, 0.01, "Secondary Redis key should have individual balance for addr2")
}

func helperInsertUserPosition(t testing.TB, ctx context.Context, db *storage.DB, userBlockchainAddr, contractAddr, tokenExternalAddr, userExternalAddr, amount string) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		INSERT INTO user_token_positions (
			user_blockchain_address, contract_address, external_address, user_external_address,
			amount, total_invested_usd, total_realized_usd, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, 0, 0, NOW())
	`, userBlockchainAddr, contractAddr, tokenExternalAddr, userExternalAddr, amount)
	require.NoError(t, err)
}

func helperUpdateTokenPairAndBaseToken(t testing.TB, ctx context.Context, db *storage.DB, tokenExternalAddr, pairID, baseToken string) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		UPDATE tokens SET pair_id = $1, base_token = $2 WHERE external_address = $3
	`, pairID, baseToken, tokenExternalAddr)

	require.NoError(t, err)
}

func TestBalanceUpdateJob_RegistersTradeInQuestDB(t *testing.T) {
	t.Parallel()
	t.Skip("stabilize quest db in tests")
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
	defer ta.Close()

	helperInsertTestUser(t, ctx, db, "test_user", "user1", "User One", "", true, PlatformGroupIonConnect)
	helperInsertBaseTokenPrice(t, ctx, db, "0x2c73996babf1a06c2c057177353293f7ca0907c8", "ION", 0.01)

	contractAddress := "0xtest_contract_001"
	tokenExternalAddress := "0:test_token_trade:"
	userBlockchainAddress := "0x1234567890123456789012345678901234567890"
	userExternalAddress := "0:user1:"
	pairID := "0x0000000000000000000000000000000000000000000000000000000000000001"
	baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
	txHash := "0xtest_trade_tx_001"

	totalSupply := "1000000000000000000000"
	helperInsertTestToken(t, ctx, db, contractAddress, tokenExternalAddress, "TEST", TokenTypeProfile, "test_user", totalSupply, 0, 0, 0, PlatformGroupIonConnect)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddress, pairID, baseToken)

	helperInsertUnprocessedSwap(t, ctx, db, contractAddress, tokenExternalAddress, userBlockchainAddress,
		txHash, false, "1000000000000000000", "10000000000000000000", 0.10, "0")

	helperInsertUserPosition(t, ctx, db, userBlockchainAddress, contractAddress, tokenExternalAddress, userExternalAddress, "10000000000000000000")

	balance := new(big.Int)
	balance.SetString("10000000000000000000", 10)
	mockBackend.SetBalanceOfResponse(balance)

	burned := new(big.Int).SetUint64(0)

	jobArgs := BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddress,
		UserExternalAddress:   userExternalAddress,
		ContractAddress:       contractAddress,
		TokenExternalAddress:  tokenExternalAddress,
		TransactionHash:       txHash,
		BlockNumber:           100,
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             TokenTypeProfile,
		Platform:              PlatformGroupIonConnect,
		Burned:                burned,
		Ticker:                "TEST",
	}

	err := ta.riverClient.Push(ctx, jobArgs)
	require.NoError(t, err)

	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	type tradeRecord struct {
		TransactionHash string  `db:"transaction_hash"`
		ContractAddress string  `db:"contract_address"`
		PriceInUsd      float64 `db:"price_in_usd"`
		TradeType       string  `db:"trade_type"`
	}

	trades, err := questdb.Select[tradeRecord](ctx, ta.questDB, `
		SELECT transaction_hash, contract_address, price_in_usd, trade_type
		FROM trades
		WHERE transaction_hash = $1 AND contract_address = $2
	`, txHash, contractAddress)

	require.NoError(t, err)
	require.Len(t, trades, 1, "Trade should be registered in QuestDB")
	require.Equal(t, txHash, trades[0].TransactionHash)
	require.Equal(t, contractAddress, trades[0].ContractAddress)
	require.Equal(t, "buy", trades[0].TradeType)
	require.Greater(t, trades[0].PriceInUsd, 0.0, "Price should be > 0")
}

func TestUpdateBondingCurveInRedis_CombinedSet(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db, WithoutQuestDB())

	t.Run("xcom_token_added_to_combined_set", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalBondingCurveProgressXcomCombinedSetKey).Err()

		err := ta.updateBondingCurveInRedis(ctx, "xcom_bc_combined_1", TokenTypeProfile, PlatformGroupXCom, 75.0, false)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomCombinedSetKey, "xcom_bc_combined_1").Result()
		require.NoError(t, err)
		require.InDelta(t, 75.0, score, 0.001)
	})

	t.Run("ionconnect_profile_added_to_combined_set", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalBondingCurveProgressXcomCombinedSetKey).Err()

		err := ta.updateBondingCurveInRedis(ctx, "0:ion_bc_combined:", TokenTypeProfile, PlatformGroupIonConnect, 50.0, false)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomCombinedSetKey, "0:ion_bc_combined:").Result()
		require.NoError(t, err)
		require.InDelta(t, 50.0, score, 0.001)
	})

	t.Run("ionconnect_post_not_in_combined_set", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalBondingCurveProgressXcomCombinedSetKey).Err()

		err := ta.updateBondingCurveInRedis(ctx, "30175:ion_bc_post:content", TokenTypePost, PlatformGroupIonConnect, 60.0, false)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomCombinedSetKey, "30175:ion_bc_post:content").Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "post token should not be in combined set")
	})

	t.Run("migrated_xcom_token_removed_from_combined_set", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalBondingCurveProgressXcomCombinedSetKey).Err()

		err := ta.updateBondingCurveInRedis(ctx, "xcom_bc_migrated", TokenTypeProfile, PlatformGroupXCom, 80.0, false)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomCombinedSetKey, "xcom_bc_migrated").Result()
		require.NoError(t, err)
		require.InDelta(t, 80.0, score, 0.001)

		err = ta.updateBondingCurveInRedis(ctx, "xcom_bc_migrated", TokenTypeProfile, PlatformGroupXCom, 0, true)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressXcomCombinedSetKey, "xcom_bc_migrated").Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "migrated token should be removed from combined set")
	})
}

func helperCreateUser(t testing.TB, ctx context.Context, db *storage.DB, userID, masterPubkey, externalAddr, username, displayName, avatar, platform string) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		INSERT INTO users (id, master_pubkey, external_address, username, display_name, avatar, platform_group, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
	`, userID, masterPubkey, externalAddr, username, displayName, avatar, platform)
	require.NoError(t, err)
}

func helperAddUserBscAddress(t testing.TB, ctx context.Context, db *storage.DB, userID, bscAddress string) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		INSERT INTO user_bsc_addresses (user_id, bsc_address, created_at) VALUES ($1, LOWER($2), NOW())
	`, userID, bscAddress)
	require.NoError(t, err)
}

func TestBalanceUpdateJob_ContentProfileInteraction(t *testing.T) {
	t.Parallel()

	const (
		ionAddress = "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		// Profile bonding curve: currentPrice=0.5 ION × ionPriceUSD=1.15 → priceUSD=0.575 per token.
		profileCurvePrice = 500000000000000000 // 0.5 base in wei
		// Content bonding curve: currentPrice=1.0 profile; with profile priceUSD=0.575 → 0.575 per token.
		contentCurvePrice = 1000000000000000000 // 1.0 base in wei
	)

	helperMakeMock := func(t *testing.T, balanceWei string, currentPriceWei int64) bondingcurve.BondingCurve {
		t.Helper()
		backend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		bal, _ := new(big.Int).SetString(balanceWei, 10)
		backend.SetBalanceOfResponse(bal)
		backend.SetBondingCurveResponse(bondingcurve.BondingCurveBondingInfo{
			CurrentPrice:      big.NewInt(currentPriceWei),
			SoldTokens:        big.NewInt(int64(1e18)),
			BondingTokensGoal: big.NewInt(int64(5e18)),
			TokensRaised:      big.NewInt(int64(1e18)),
			EndPrice:          big.NewInt(int64(1e17)),
			StartPrice:        big.NewInt(int64(1e18)),
			Migrated:          false,
		})
		return bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(backend)
	}

	// profilePriceUSD = profileCurvePrice(0.5 ION) × ionPriceUSD(1.15) = 0.575
	// contentPriceUSD  = contentCurvePrice(1.0 profile) × profilePriceUSD(0.575) = 0.575
	const profilePriceUSD = 0.575

	// 1. Twisted buy (ION → content via FatAddress V2, profile auto-created)
	t.Run("twisted_buy_first_content_purchase", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTest(t, db, WithRealRiverQueue(connString),
			WithBondingCurve(helperMakeMock(t, "50000000000000000000", profileCurvePrice)),
			WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xaa00000000000000000000000000000000000011"
		userExt := "0:twisted_first_user:"
		txHash := "0xtwisted_first_tx_001"

		profileContract := "0xbb00000000000000000000000000000000000011"
		profileTokenExt := "0:twisted_first_user:profile"
		profilePairID := "0x0000000000000000000000000000000000000000000000000000000000000199"

		contentContract := "0xcc00000000000000000000000000000000000011"
		contentTokenExt := "0:twisted_first_user:post"
		contentPairID := "0x0000000000000000000000000000000000000000000000000000000000000198"

		helperInsertTestUser(t, ctx, db, userExt, "twisted_first_user", "Twisted First User", userAddr, false, PlatformGroupIonConnect)

		helperInsertTestToken(t, ctx, db, profileContract, profileTokenExt, "TPROF1", TokenTypeProfile, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, profileTokenExt, profilePairID, ionAddress)
		helperInsertBaseTokenPrice(t, ctx, db, ionAddress, "ION", 0.01)
		helperInsertUserPosition(t, ctx, db, userAddr, profileContract, profileTokenExt, userExt, "0")

		helperInsertTestToken(t, ctx, db, contentContract, contentTokenExt, "TCONT1", TokenTypePost, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, contentTokenExt, contentPairID, profileContract)
		helperInsertBaseTokenPrice(t, ctx, db, profileContract, "TPROF1", profilePriceUSD)
		helperInsertUserPosition(t, ctx, db, userAddr, contentContract, contentTokenExt, userExt, "0")
		// Only content token_swaps entry exists (twisted swap via FatAddress V2).
		// User paid 10 ION (via profile intermediary), received 50 content tokens.
		// No profile token_swaps entry — profile is just a pass-through.
		helperInsertUnprocessedSwap(t, ctx, db, contentContract, contentTokenExt, userAddr,
			txHash, false, "950000000000000000000", "50000000000000000000", profilePriceUSD, "0")

		// Job 1: content invested (from twisted swap)
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       contentContract,
			TokenExternalAddress:  contentTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           12345,
			PairID:                contentPairID,
			BaseToken:             profileContract,
			TokenType:             TokenTypePost,
			Platform:              PlatformGroupIonConnect,
		}))
		// Job 2: baseJobArgs for profile balance (no token_swaps entry for profile → PnL no-op)
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       profileContract,
			TokenExternalAddress:  profileTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           12345,
			PairID:                profilePairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type pos struct {
			Amount           string  `db:"amount"`
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		// Content: invested = LEAST(50, 50)/50 × 950 × profilePriceUSD = 1 × 950 × 0.575 = 546.25
		contGot, err := storage.Get[pos](ctx, db, `
			SELECT amount, total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contentContract))
		require.NoError(t, err)
		require.InDelta(t, 546.25, contGot.TotalInvestedUSD, 1.0, "content invested = input_profile * profilePriceUSD (950 * 0.575)")
		require.InDelta(t, 0.0, contGot.TotalRealizedUSD, 0.001, "content realized must be zero on buy")

		// Profile: invested and realized must remain zero (no token_swaps entry for profile).
		// baseJobArgs only updates balance; PnL SQL finds no swap_update rows → no-op.
		profGot, err := storage.Get[pos](ctx, db, `
			SELECT amount, total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(profileContract))
		require.NoError(t, err)
		require.Equal(t, "50000000000000000000", profGot.Amount, "profile balance should be 50 remaining tokens")
		require.InDelta(t, 0.0, profGot.TotalInvestedUSD, 0.001, "profile invested must be zero: no token_swaps entry for profile (twisted buy via FatAddress V2)")
		require.InDelta(t, 0.0, profGot.TotalRealizedUSD, 0.001, "profile realized must be zero: profile is just a pass-through")
	})

	// 2. Double buy (ION → profile, then profile → content in same tx): verifies that profile.invested
	//    only reflects the proportional cost of the REMAINING profile tokens (LEAST formula), not the
	//    full ION paid, and that profile.realized is zero (spending profile on content is NOT a realization).
	t.Run("double_buy_profile_invested_proportional_to_remaining", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTest(t, db, WithRealRiverQueue(connString),
			WithBondingCurve(helperMakeMock(t, "50000000000000000000", profileCurvePrice)), // 50 tokens
			WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xaa00000000000000000000000000000000000001"
		userExt := "0:twisted_user:"
		txHash := "0xtwisted_tx_001"

		profileContract := "0xbb00000000000000000000000000000000000001"
		profileTokenExt := "0:twisted_user:profile"
		profilePairID := "0x0000000000000000000000000000000000000000000000000000000000000099"

		contentContract := "0xcc00000000000000000000000000000000000001"
		contentTokenExt := "0:twisted_user:post"
		contentPairID := "0x0000000000000000000000000000000000000000000000000000000000000098"

		helperInsertTestUser(t, ctx, db, userExt, "twisted_user", "Twisted User", userAddr, false, PlatformGroupIonConnect)

		// Profile token (base=ION): user paid 10 ION and got 1000 profile tokens.
		helperInsertTestToken(t, ctx, db, profileContract, profileTokenExt, "TPROF", TokenTypeProfile, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, profileTokenExt, profilePairID, ionAddress)
		helperInsertBaseTokenPrice(t, ctx, db, ionAddress, "ION", 0.01)
		helperInsertUserPosition(t, ctx, db, userAddr, profileContract, profileTokenExt, userExt, "0")
		helperInsertUnprocessedSwap(t, ctx, db, profileContract, profileTokenExt, userAddr,
			txHash, false, "10000000000000000000", "1000000000000000000000", 0.01, "0")

		// Content token (base=profile): 950 of those profile tokens were immediately spent on content.
		// output=50e18 matches mock balance (50 tokens), so LEAST(output, balance)=output → full invested.
		helperInsertTestToken(t, ctx, db, contentContract, contentTokenExt, "TCONT", TokenTypePost, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, contentTokenExt, contentPairID, profileContract)
		helperInsertBaseTokenPrice(t, ctx, db, profileContract, "TPROF", profilePriceUSD) // profile price for content's basePriceUSD lookup
		helperInsertUserPosition(t, ctx, db, userAddr, contentContract, contentTokenExt, userExt, "0")
		helperInsertUnprocessedSwap(t, ctx, db, contentContract, contentTokenExt, userAddr,
			txHash, false, "950000000000000000000", "50000000000000000000", profilePriceUSD, "0")

		// Job 1: profile invested (from ION→profile swap)
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       profileContract,
			TokenExternalAddress:  profileTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           12345,
			PairID:                profilePairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		// Job 2: content invested (from profile→content swap)
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       contentContract,
			TokenExternalAddress:  contentTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           12345,
			PairID:                contentPairID,
			BaseToken:             profileContract,
			TokenType:             TokenTypePost,
			Platform:              PlatformGroupIonConnect,
		}))
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type pos struct {
			Amount           string  `db:"amount"`
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		// Profile: invested = LEAST(output=1000, balance=50)/1000 × input=10 × ionPriceUSD=1.15
		//          = 50/1000 × 10 × 1.15 = 0.575  (only the cost of the 50 remaining tokens)
		//          realized = 0  (exchanging profile for content is NOT a realization event)
		profGot, err := storage.Get[pos](ctx, db, `
			SELECT amount, total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(profileContract))
		require.NoError(t, err)
		require.Equal(t, "50000000000000000000", profGot.Amount, "profile balance should be 50 remaining tokens")
		require.InDelta(t, 0.575, profGot.TotalInvestedUSD, 0.01, "profile invested = (remaining/total) * input_ION * ionPriceUSD = (50/1000)*10*1.15")
		require.InDelta(t, 0.0, profGot.TotalRealizedUSD, 0.001, "profile realized must be zero: exchange is not a realization")

		// Content: invested = LEAST(output=50, balance=50)/50 × input=950 × profilePriceUSD=0.575
		//          = 1 × 950 × 0.575 = 546.25
		contGot, err := storage.Get[pos](ctx, db, `
			SELECT amount, total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contentContract))
		require.NoError(t, err)
		require.InDelta(t, 546.25, contGot.TotalInvestedUSD, 1.0, "content invested = input_profile * profilePriceUSD (950 * 0.575)")
		require.InDelta(t, 0.0, contGot.TotalRealizedUSD, 0.001, "content realized must be zero on buy")
	})

	// 3. profile → ION (1+ sell): user sells profile tokens and receives ION.
	//    profile.total_realized_usd must increase by output_ION × basePriceUSD (ionPriceUSD).
	t.Run("profile_sell_updates_realized", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTest(t, db, WithRealRiverQueue(connString),
			WithBondingCurve(helperMakeMock(t, "95000000000000000000", profileCurvePrice)), // 95 remaining
			WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xba00000000000000000000000000000000000001"
		userExt := "0:profile_sell_user:"
		contract := "0xcb00000000000000000000000000000000000001"
		tokenExt := "0:profile_sell_user:profile"
		txHash := "0xprofile_sell_tx_001"
		pairID := "0x000000000000000000000000000000000000000000000000000000000000cccc"

		helperInsertTestUser(t, ctx, db, userExt, "profile_sell_user", "Profile Sell User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, contract, tokenExt, "PSELL", "profile", userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExt, pairID, ionAddress)
		helperInsertBaseTokenPrice(t, ctx, db, ionAddress, "ION", 0.01)
		// Initial balance = 100 tokens (user held 100 profile before selling 5).
		// prevBalance formula: GREATEST(0, 100-95)/5 = 1 → full realized.
		helperInsertUserPosition(t, ctx, db, userAddr, contract, tokenExt, userExt, "100000000000000000000")
		// direction=true (sell): user sends 5 profile tokens, receives 2.5 ION
		helperInsertUnprocessedSwap(t, ctx, db, contract, tokenExt, userAddr,
			txHash, true, "5000000000000000000", "2500000000000000000", 0.575, "0")

		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       contract,
			TokenExternalAddress:  tokenExt,
			TransactionHash:       txHash,
			BlockNumber:           20000,
			PairID:                pairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type pos struct {
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		got, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contract))
		require.NoError(t, err)
		require.InDelta(t, 0.0, got.TotalInvestedUSD, 0.001, "sell must not affect invested")
		// realized = output_ION × ionPriceUSD = 2.5 × 1.15 = 2.875
		require.InDelta(t, 2.875, got.TotalRealizedUSD, 0.01, "realized = output_ION * ionPriceUSD (2.5 * 1.15)")
	})

	// 4. profile → content (buy): user spends 50 profile tokens to buy content tokens.
	//    content.invested += 50_profile × profilePriceUSD.
	t.Run("content_buy_with_profile_base", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		profileContractAddr := "0xdc00000000000000000000000000000000000001"
		profileTokenExt := "0:content_buy_user:profile"
		profileOwnPairID := "0x000000000000000000000000000000000000000000000000000000000000cccc"

		contentContractAddr := "0xed00000000000000000000000000000000000001"
		contentTokenExt := "0:content_buy_user:post"
		contentPairID := "0x000000000000000000000000000000000000000000000000000000000000dddd"

		// contentPriceUSD = 0.5 × profilePriceUSD = 0.2875 (unused for invested/realized here).
		ta := helperNewForTest(t, db, WithRealRiverQueue(connString),
			WithBondingCurve(helperMakeMock(t, "50000000000000000000", profileCurvePrice)),
			WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xcb00000000000000000000000000000000000002"
		userExt := "0:content_buy_user:"
		txHash := "0xcontent_buy_tx_001"

		helperInsertTestUser(t, ctx, db, userExt, "content_buy_user", "Content Buy User", userAddr, false, PlatformGroupIonConnect)

		// Profile token (base=ION)
		helperInsertTestToken(t, ctx, db, profileContractAddr, profileTokenExt, "PBUY", TokenTypeProfile, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, profileTokenExt, profileOwnPairID, ionAddress)
		helperInsertUserPosition(t, ctx, db, userAddr, profileContractAddr, profileTokenExt, userExt, "0")

		// Content token (base=profile)
		helperInsertTestToken(t, ctx, db, contentContractAddr, contentTokenExt, "CBUY", TokenTypePost, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, contentTokenExt, contentPairID, profileContractAddr)
		helperInsertBaseTokenPrice(t, ctx, db, profileContractAddr, "PBUY", profilePriceUSD)
		helperInsertUserPosition(t, ctx, db, userAddr, contentContractAddr, contentTokenExt, userExt, "0")
		// direction=false (buy): user spends 50 profile tokens, receives 50 content tokens
		helperInsertUnprocessedSwap(t, ctx, db, contentContractAddr, contentTokenExt, userAddr,
			txHash, false, "50000000000000000000", "50000000000000000000", profilePriceUSD, "0")

		// Job 1: content invested.
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       contentContractAddr,
			TokenExternalAddress:  contentTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           30000,
			PairID:                contentPairID,
			BaseToken:             profileContractAddr,
			TokenType:             TokenTypePost,
			Platform:              PlatformGroupIonConnect,
		}))
		// baseJobArgs: profile balance update only (no PnL fields); must not alter profile invested/realized
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       profileContractAddr,
			TokenExternalAddress:  profileTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           30000,
			PairID:                profileOwnPairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type pos struct {
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		// Content: invested = LEAST(50, 50)/50 × 50 × profilePriceUSD = 1 × 50 × 0.575 = 28.75
		contGot, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contentContractAddr))
		require.NoError(t, err)
		require.InDelta(t, 28.75, contGot.TotalInvestedUSD, 0.1, "content invested = input_profile * profilePriceUSD (50 * 0.575)")
		require.InDelta(t, 0.0, contGot.TotalRealizedUSD, 0.001, "content realized must be zero on buy")

		// Profile: invested and realized must remain zero.
		profGot, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(profileContractAddr))
		require.NoError(t, err)
		require.InDelta(t, 0.0, profGot.TotalInvestedUSD, 0.001, "profile invested must not change: spending profile on content is not a cost-basis event here")
		require.InDelta(t, 0.0, profGot.TotalRealizedUSD, 0.001, "profile realized must not change: exchange for content is not a realization")
	})

	// 5. content → profile (sell): user sells content and receives profile tokens (no further sell).
	//    content.realized += profile_received × profilePriceUSD.
	t.Run("content_sell_with_profile_base", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		profileContractAddr := "0xfe00000000000000000000000000000000000001"
		profileTokenExt := "0:content_sell_user:profile"
		profileOwnPairID := "0x000000000000000000000000000000000000000000000000000000000000ffff"

		contentContractAddr := "0x0f00000000000000000000000000000000000001"
		contentTokenExt := "0:content_sell_user:post"
		contentPairID := "0x000000000000000000000000000000000000000000000000000000000000eeee"

		ta := helperNewForTest(t, db, WithRealRiverQueue(connString),
			WithBondingCurve(helperMakeMock(t, "20000000000000000000", profileCurvePrice)),
			WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xdc00000000000000000000000000000000000002"
		userExt := "0:content_sell_user:"
		txHash := "0xcontent_sell_tx_001"

		helperInsertTestUser(t, ctx, db, userExt, "content_sell_user", "Content Sell User", userAddr, false, PlatformGroupIonConnect)

		helperInsertTestToken(t, ctx, db, profileContractAddr, profileTokenExt, "PSELL", TokenTypeProfile, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, profileTokenExt, profileOwnPairID, ionAddress)
		helperInsertUserPosition(t, ctx, db, userAddr, profileContractAddr, profileTokenExt, userExt, "0")

		helperInsertTestToken(t, ctx, db, contentContractAddr, contentTokenExt, "CSELL", TokenTypePost, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, contentTokenExt, contentPairID, profileContractAddr)
		helperInsertBaseTokenPrice(t, ctx, db, profileContractAddr, "PSELL", profilePriceUSD)
		// Initial content balance = 50e18 (user held 50 before selling 30; mock returns 20e18 remaining).
		// prevBalance formula: GREATEST(50-20, 0)/30 = 1 → full realized.
		helperInsertUserPosition(t, ctx, db, userAddr, contentContractAddr, contentTokenExt, userExt, "50000000000000000000")
		// direction=true (sell): user sends 30 content tokens, receives 100 profile tokens
		helperInsertUnprocessedSwap(t, ctx, db, contentContractAddr, contentTokenExt, userAddr,
			txHash, true, "30000000000000000000", "100000000000000000000", profilePriceUSD, "0")

		// Job 1: content realized.
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       contentContractAddr,
			TokenExternalAddress:  contentTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           30001,
			PairID:                contentPairID,
			BaseToken:             profileContractAddr,
			TokenType:             TokenTypePost,
			Platform:              PlatformGroupIonConnect,
		}))
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       profileContractAddr,
			TokenExternalAddress:  profileTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           30001,
			PairID:                profileOwnPairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type pos struct {
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		// Content: realized = output_profile × profilePriceUSD = 100 × 0.575 = 57.5
		contGot, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contentContractAddr))
		require.NoError(t, err)
		require.InDelta(t, 0.0, contGot.TotalInvestedUSD, 0.001, "content invested must be zero on sell")
		require.InDelta(t, 57.5, contGot.TotalRealizedUSD, 0.1, "content realized = output_profile * profilePriceUSD (100 * 0.575)")

		// Profile: invested and realized must remain zero.
		profGot, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(profileContractAddr))
		require.NoError(t, err)
		require.InDelta(t, 0.0, profGot.TotalInvestedUSD, 0.001, "profile invested must not change: receiving profile from content sell is not a cost-basis event")
		require.InDelta(t, 0.0, profGot.TotalRealizedUSD, 0.001, "profile realized must not change: no ION→profile swap in this tx")
	})

	// 6. Full double sell (content → profile → ION)
	t.Run("double_sell_profile_realized_is_zero", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		profileContract := "0xaa10000000000000000000000000000000000001"
		profileTokenExt := "0:double_sell_user:profile"
		profilePairID := "0x0000000000000000000000000000000000000000000000000000000000001111"

		contentContract := "0xbb10000000000000000000000000000000000001"
		contentTokenExt := "0:double_sell_user:post"
		contentPairID := "0x0000000000000000000000000000000000000000000000000000000000002222"

		// Profile final balance = 50e18 (had 50 originally; received 100 from content sell,
		// immediately sold 100 for ION → net change = 0).
		// Content balance after sell = 50e18 (had 80, sold 30 → 50 remaining).
		ta := helperNewForTest(t, db, WithRealRiverQueue(connString),
			WithBondingCurve(helperMakeMock(t, "50000000000000000000", profileCurvePrice)),
			WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xcc10000000000000000000000000000000000001"
		userExt := "0:double_sell_user:"
		txHash := "0xdouble_sell_tx_001"

		helperInsertTestUser(t, ctx, db, userExt, "double_sell_user", "Double Sell User", userAddr, false, PlatformGroupIonConnect)

		// Profile token (base=ION): user had 50 profile before this double-sell transaction.
		helperInsertTestToken(t, ctx, db, profileContract, profileTokenExt, "DPROF", TokenTypeProfile, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, profileTokenExt, profilePairID, ionAddress)
		helperInsertBaseTokenPrice(t, ctx, db, ionAddress, "ION", 0.01)
		helperInsertUserPosition(t, ctx, db, userAddr, profileContract, profileTokenExt, userExt, "50000000000000000000")
		// Profile→ION sell (intermediate step): user sells 100 profile (received from content sell), gets 2.5 ION.
		helperInsertUnprocessedSwap(t, ctx, db, profileContract, profileTokenExt, userAddr,
			txHash, true, "100000000000000000000", "2500000000000000000", 0.575, "0")

		// Content token (base=profile): user had 80 content before selling 30.
		helperInsertTestToken(t, ctx, db, contentContract, contentTokenExt, "DCONT", TokenTypePost, userExt, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, contentTokenExt, contentPairID, profileContract)
		helperInsertBaseTokenPrice(t, ctx, db, profileContract, "DPROF", profilePriceUSD)
		helperInsertUserPosition(t, ctx, db, userAddr, contentContract, contentTokenExt, userExt, "80000000000000000000")
		// Content→profile sell: user sends 30 content, receives 100 profile tokens.
		helperInsertUnprocessedSwap(t, ctx, db, contentContract, contentTokenExt, userAddr,
			txHash, true, "30000000000000000000", "100000000000000000000", profilePriceUSD, "0")

		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       contentContract,
			TokenExternalAddress:  contentTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           40000,
			PairID:                contentPairID,
			BaseToken:             profileContract,
			TokenType:             TokenTypePost,
			Platform:              PlatformGroupIonConnect,
		}))
		// Since prevBalance(=50) == finalBalance(=50), realized = 0.
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       profileContract,
			TokenExternalAddress:  profileTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           40000,
			PairID:                profilePairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		// Profile job (from profile→ION event): curve_price_usd already set by baseJobArgs → no-op.
		require.NoError(t, ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExt,
			ContractAddress:       profileContract,
			TokenExternalAddress:  profileTokenExt,
			TransactionHash:       txHash,
			BlockNumber:           40000,
			PairID:                profilePairID,
			BaseToken:             ionAddress,
			TokenType:             TokenTypeProfile,
			Platform:              PlatformGroupIonConnect,
		}))
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type pos struct {
			TotalInvestedUSD float64 `db:"total_invested_usd"`
			TotalRealizedUSD float64 `db:"total_realized_usd"`
		}
		// Content: realized = GREATEST(80-50, 0)/30 × 100 × profilePriceUSD = 1 × 100 × 0.575 = 57.5
		contGot, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contentContract))
		require.NoError(t, err)
		require.InDelta(t, 0.0, contGot.TotalInvestedUSD, 0.001, "content invested must be zero on sell")
		require.InDelta(t, 57.5, contGot.TotalRealizedUSD, 0.1, "content realized = (80-50)/30 * 100 * profilePriceUSD = 57.5")

		// Profile: realized = GREATEST(50-50, 0)/100 × 2.5 × ionPriceUSD = 0
		// baseJobArgs processes the profile→ION token_swaps first (same txHash), setting curve_price_usd.
		// prevBalance (50) == finalBalance (50) → pass-through detected → no realized added.
		profGot, err := storage.Get[pos](ctx, db, `
			SELECT total_invested_usd, total_realized_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(profileContract))
		require.NoError(t, err)
		require.InDelta(t, 0.0, profGot.TotalInvestedUSD, 0.001, "profile invested must not change")
		require.InDelta(t, 0.0, profGot.TotalRealizedUSD, 0.001, "profile realized must be zero: pass-through detected (prevBalance == finalBalance = 50)")
	})
}

func TestBalanceUpdateJob_FeeInOtherToken(t *testing.T) {
	t.Parallel()

	t.Run("fee_in_base_token", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBackend.SetBalanceOfResponse(big.NewInt(5000000000000000000)) // 5 tokens
		mockBackend.SetBondingCurveResponse(bondingcurve.BondingCurveBondingInfo{
			CurrentPrice:      big.NewInt(500000000000000000), // 0.5 base
			SoldTokens:        big.NewInt(int64(1e18)),
			BondingTokensGoal: big.NewInt(int64(5e18)),
			TokensRaised:      big.NewInt(int64(1e18)),
			EndPrice:          big.NewInt(int64(1e17)),
			StartPrice:        big.NewInt(int64(1e18)),
			Migrated:          false,
		})
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xcc00000000000000000000000000000000000001"
		userExtAddr := "0:fee_base_user:"
		contractAddr := "0xdd00000000000000000000000000000000000001"
		tokenExtAddr := "0:fee_base_user:token"
		txHash := "0xfee_base_tx_001"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000011"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

		helperInsertTestUser(t, ctx, db, userExtAddr, "fee_base_user", "Fee Base User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, contractAddr, tokenExtAddr, "FBT", "profile", userExtAddr, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExtAddr, pairID, baseToken)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperSetFeeInOtherToken(t, ctx, db, contractAddr, false)
		helperInsertUserPosition(t, ctx, db, userAddr, contractAddr, tokenExtAddr, userExtAddr, "0")

		// fee = 2e18 in base token (ION). fee_in_other_token = false → fee_usd = 2 * 0.5 = 1.0
		helperInsertUnprocessedSwap(t, ctx, db, contractAddr, tokenExtAddr, userAddr,
			txHash, false, "10000000000000000000", "5000000000000000000", 0.01, "2000000000000000000")

		err := ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExtAddr,
			ContractAddress:       contractAddr,
			TokenExternalAddress:  tokenExtAddr,
			TransactionHash:       txHash,
			BlockNumber:           100,
			PairID:                pairID,
			BaseToken:             baseToken,
			TokenType:             "profile",
			Platform:              PlatformGroupIonConnect,
		})
		require.NoError(t, err)
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type position struct {
			TotalFeesUSD float64 `db:"total_fees_usd"`
		}
		pos, err := storage.Get[position](ctx, db, `
			SELECT total_fees_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contractAddr))
		require.NoError(t, err)
		// fee_in_other_token=FALSE: fee_usd = (2e18 / 1e18) * basePriceUSD = 2 * 1.15 = 2.3
		// basePriceUSD = ionPriceUSD = 1.15 (from calculatePriceInUSD for ION base token)
		require.InDelta(t, 2.3, pos.TotalFeesUSD, 0.001, "Fee in base token: fee * basePriceUSD (ionPrice)")
	})

	t.Run("fee_in_other_token_true", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
		mockBackend.SetBalanceOfResponse(big.NewInt(5000000000000000000)) // 5 tokens
		mockBackend.SetBondingCurveResponse(bondingcurve.BondingCurveBondingInfo{
			CurrentPrice:      big.NewInt(500000000000000000), // 0.5 base
			SoldTokens:        big.NewInt(int64(1e18)),
			BondingTokensGoal: big.NewInt(int64(5e18)),
			TokensRaised:      big.NewInt(int64(1e18)),
			EndPrice:          big.NewInt(int64(1e17)),
			StartPrice:        big.NewInt(int64(1e18)),
			Migrated:          false,
		})
		mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

		ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
		defer ta.Close()

		userAddr := "0xee00000000000000000000000000000000000001"
		userExtAddr := "0:fee_other_user:"
		contractAddr := "0xff00000000000000000000000000000000000001"
		tokenExtAddr := "0:fee_other_user:token"
		txHash := "0xfee_other_tx_001"
		pairID := "0x0000000000000000000000000000000000000000000000000000000000000012"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

		helperInsertTestUser(t, ctx, db, userExtAddr, "fee_other_user", "Fee Other User", userAddr, false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, contractAddr, tokenExtAddr, "FOT", "post", userExtAddr, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExtAddr, pairID, baseToken)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.5)
		helperSetFeeInOtherToken(t, ctx, db, contractAddr, true)
		helperInsertUserPosition(t, ctx, db, userAddr, contractAddr, tokenExtAddr, userExtAddr, "0")

		// fee = 3e18 in the token itself. fee_in_other_token = true → fee_usd = 3 * curve_price
		// curve_price = 0.5 base * 1.15 ion = 0.575 USD
		// fee_usd = 3 * 0.575 = 1.725
		helperInsertUnprocessedSwap(t, ctx, db, contractAddr, tokenExtAddr, userAddr,
			txHash, false, "10000000000000000000", "5000000000000000000", 0.01, "3000000000000000000")

		err := ta.riverClient.Push(ctx, BalanceUpdateJobArgs{
			UserBlockchainAddress: userAddr,
			UserExternalAddress:   userExtAddr,
			ContractAddress:       contractAddr,
			TokenExternalAddress:  tokenExtAddr,
			TransactionHash:       txHash,
			BlockNumber:           100,
			PairID:                pairID,
			BaseToken:             baseToken,
			TokenType:             TokenTypePost,
			Platform:              PlatformGroupIonConnect,
		})
		require.NoError(t, err)
		helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

		type position struct {
			TotalFeesUSD float64 `db:"total_fees_usd"`
		}
		pos, err := storage.Get[position](ctx, db, `
			SELECT total_fees_usd FROM user_token_positions
			WHERE user_blockchain_address = $1 AND contract_address = $2
		`, strings.ToLower(userAddr), strings.ToLower(contractAddr))
		require.NoError(t, err)
		// fee_in_other_token=TRUE: fee_usd = (3e18 / 1e18) * curve_price = 3 * 0.575 = 1.725
		require.InDelta(t, 1.725, pos.TotalFeesUSD, 0.001, "Fee in other token: fee * curve_price")
	})
}

func TestBalanceUpdateJob_GuardIdempotency(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	mockBackend, _, _ := bondingcurvefixture.SetupMockedBondingCurveBackend(t, bondingcurvefixture.DefaultMockBackendConfig())
	mockBackend.SetBalanceOfResponse(big.NewInt(5000000000000000000)) // 5 tokens
	mockBackend.SetBondingCurveResponse(bondingcurve.BondingCurveBondingInfo{
		CurrentPrice:      big.NewInt(500000000000000000), // 0.5 base
		SoldTokens:        big.NewInt(int64(1e18)),
		BondingTokensGoal: big.NewInt(int64(5e18)),
		TokensRaised:      big.NewInt(int64(1e18)),
		EndPrice:          big.NewInt(int64(1e17)),
		StartPrice:        big.NewInt(int64(1e18)),
		Migrated:          false,
	})
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC), WithoutQuestDB())
	defer ta.Close()

	userAddr := "0xab00000000000000000000000000000000000001"
	userExtAddr := "0:idempotent_user:"
	contractAddr := "0xac00000000000000000000000000000000000001"
	tokenExtAddr := "0:idempotent_user:token"
	txHash := "0xidempotent_tx_001"
	pairID := "0x0000000000000000000000000000000000000000000000000000000000000055"
	baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

	helperInsertTestUser(t, ctx, db, userExtAddr, "idempotent_user", "Idempotent User", userAddr, false, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, contractAddr, tokenExtAddr, "IDEM", "profile", userExtAddr, "1000000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExtAddr, pairID, baseToken)
	helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.01)
	helperInsertUserPosition(t, ctx, db, userAddr, contractAddr, tokenExtAddr, userExtAddr, "0")

	helperInsertUnprocessedSwap(t, ctx, db, contractAddr, tokenExtAddr, userAddr,
		txHash, false, "1000000000000000000", "5000000000000000000", 0.10, "0")

	jobArgs := BalanceUpdateJobArgs{
		UserBlockchainAddress: userAddr,
		UserExternalAddress:   userExtAddr,
		ContractAddress:       contractAddr,
		TokenExternalAddress:  tokenExtAddr,
		TransactionHash:       txHash,
		BlockNumber:           12345,
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             "profile",
		Platform:              PlatformGroupIonConnect,
	}

	err := ta.riverClient.Push(ctx, jobArgs)
	require.NoError(t, err)
	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	type position struct {
		TotalInvestedUSD float64 `db:"total_invested_usd"`
	}
	pos1, err := storage.Get[position](ctx, db, `
		SELECT total_invested_usd FROM user_token_positions
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, strings.ToLower(userAddr), strings.ToLower(contractAddr))
	require.NoError(t, err)
	require.Greater(t, pos1.TotalInvestedUSD, 0.0, "First job should set invested")

	// Push the same job again — guard (curve_price_usd = 0) prevents double-count.
	err = ta.riverClient.Push(ctx, jobArgs)
	require.NoError(t, err)
	helperWaitForRiverQueueJobs(t, ctx, ta, 10*time.Second)

	pos2, err := storage.Get[position](ctx, db, `
		SELECT total_invested_usd FROM user_token_positions
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, strings.ToLower(userAddr), strings.ToLower(contractAddr))
	require.NoError(t, err)
	require.InDelta(t, pos1.TotalInvestedUSD, pos2.TotalInvestedUSD, 0.0001, "Second job must NOT increment invested again")
}

func helperInsertUnprocessedSwap(t testing.TB, ctx context.Context, db *storage.DB,
	contractAddr, externalAddr, userAddr, txHash string,
	direction bool, inputAmount, outputAmount string, priceUSD float64, fee string) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_blockchain_address, direction, input_amount, output_amount, price_usd, fee, curve_price_usd
		)
		VALUES (NOW(), $1, $2, $3, LOWER($4), $5, $6, $7, $8, $9, 0)
		ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING
	`, txHash, contractAddr, externalAddr, userAddr, direction, inputAmount, outputAmount, priceUSD, fee)
	require.NoError(t, err)
}

func helperSetFeeInOtherToken(t testing.TB, ctx context.Context, db *storage.DB, contractAddr string, feeInOther bool) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `UPDATE tokens SET fee_in_other_token = $1 WHERE contract_address = $2`, feeInOther, contractAddr)
	require.NoError(t, err)
}
