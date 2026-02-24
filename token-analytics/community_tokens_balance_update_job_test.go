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

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
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
	mockBC := bondingcurvefixture.CreateMockedBondingCurveForBalanceTests(mockBackend)

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

	helperInsertBaseTokenPrice(t, ctx, db, "0x2c73996babf1a06c2c057177353293f7ca0907c8", "ION", 0.01)
	helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, "0x0000000000000000000000000000000000000000000000000000000000000001", "0x2c73996babf1a06c2c057177353293f7ca0907c8")

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
		Amount string `db:"amount"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount FROM user_token_positions
		WHERE user_blockchain_address = $1 AND contract_address = $2
	`, strings.ToLower(userBlockchainAddr), strings.ToLower(tokenContractAddr))
	require.NoError(t, err)
	require.Equal(t, "5000000000000000000", pos.Amount, "Balance should be updated to 5 tokens")

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

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
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

	ta := helperNewForTest(t, db, WithRealRiverQueue(connString), WithBondingCurve(mockBC))
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
		Amount string `db:"amount"`
	}
	pos, err := storage.Get[position](ctx, db, `
		SELECT amount FROM user_token_positions 
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

	helperInsertTokenSwap(t, ctx, db, contractAddress, tokenExternalAddress, userBlockchainAddress,
		txHash, false, "1000000000000000000", "10000000000000000000", 0.10)

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
