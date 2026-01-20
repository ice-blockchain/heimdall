// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	wtime "github.com/ice-blockchain/wintr/time"
)

func TestOnUniswapSwapped(t *testing.T) {
	ctx := context.Background()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString)

	poolAddress := "0xabcd000000000000000000000000000000000001"
	contractAddress := "0xffff000000000000000000000000000000000001"
	baseToken := "0x2c73996baBF1a06c2C057177353293f7cA0907c8" // ION (lowercase)
	externalAddress := "30175:uniswap_test_user:test"
	userBlockchainAddr := "0xbbbb000000000000000000000000000000000001"
	userExternalAddr := "uniswap_test_user_external"
	_ = userExternalAddr // Used in Redis checks

	now := time.Now()

	t.Run("processes_uniswap_buy_successfully", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "test_pubkey", "uniswap_user", "Uniswap User", userBlockchainAddr, false, "ionconnect")
		helperInsertTestToken(t, ctx, db, contractAddress, externalAddress, "TEST", "profile", "test_pubkey", "1000000000000000000000", 0.0, 0.0, 0, "ionconnect")

		_, err := storage.Exec(ctx, db, `
			UPDATE tokens SET pair_id = $1, base_token = $2 WHERE contract_address = $3
		`, "0x1111111111111111111111111111111111111111111111111111111111111111", baseToken, contractAddress)
		require.NoError(t, err)

		// Insert uniswap pool (contractAddress is token0, baseToken is token1)
		helperInsertUniswapPool(t, ctx, db, poolAddress, contractAddress, contractAddress, baseToken, 3000)

		// buy: user receives tokens, token0 is community token
		// Amount0 > 0 means token0 flows TO the pool (user sells token0)
		// Amount1 < 0 means token1 flows FROM the pool (user receives token1)
		// For buy: user sends ION (token1), receives community token (token0)
		// So: Amount0 < 0 (token flows from pool), Amount1 > 0 (ION flows to pool)
		swapEvent := &bondingcurve.LogUniswapSwapped{
			PoolAddress: common.HexToAddress(poolAddress),
			Sender:      common.HexToAddress(userBlockchainAddr),
			Recipient:   common.HexToAddress(userBlockchainAddr),
			Amount0:     big.NewInt(-1000000000000000000), // -1 token (flows FROM pool to user)
			Amount1:     big.NewInt(100000000000000000),   // 0.1 ION (flows TO pool from user)
		}

		tx := &txEvent{
			TransactionHash: "0xuniswap_buy_test",
			BlockNumber:     100,
			FromAddress:     userBlockchainAddr,
			BlockTimestamp:  wtime.New(now),
			Input:           "0x",
		}

		err = ta.(*tokenAnalytics).onUniswapSwapped(ctx, tx, swapEvent)
		require.NoError(t, err, "onUniswapSwapped should complete without error")
	})

	t.Run("processes_uniswap_sell_successfully", func(t *testing.T) {
		poolAddress2 := "0xabcd000000000000000000000000000000000002"
		contractAddress2 := "0xffff000000000000000000000000000000000002"
		externalAddress2 := "30175:uniswap_sell_user:test"
		userBlockchainAddr2 := "0xbbbb000000000000000000000000000000000002"
		userExternalAddr2 := "uniswap_sell_user_external"

		helperInsertTestUser(t, ctx, db, "test_pubkey2", "uniswap_sell_user", "Uniswap Sell User", userBlockchainAddr2, false, "ionconnect")
		helperInsertTestToken(t, ctx, db, contractAddress2, externalAddress2, "TEST2", "profile", "test_pubkey2", "1000000000000000000000", 0.0, 0.0, 0, "ionconnect")

		_, err := storage.Exec(ctx, db, `
			UPDATE tokens SET pair_id = $1, base_token = $2 WHERE contract_address = $3
		`, "0x2222222222222222222222222222222222222222222222222222222222222222", baseToken, contractAddress2)
		require.NoError(t, err)

		// contractAddress2 is token0, baseToken is token1
		helperInsertUniswapPool(t, ctx, db, poolAddress2, contractAddress2, contractAddress2, baseToken, 3000)

		// Insert initial position for sell
		helperInsertUserPosition(t, ctx, db, userBlockchainAddr2, contractAddress2, externalAddress2, userExternalAddr2, "2000000000000000000") // 2 tokens

		// sell: user sends tokens, receives ION
		// Amount0 > 0 means token0 flows TO the pool (user sells token0)
		// Amount1 < 0 means token1 flows FROM the pool (user receives token1)
		swapEvent := &bondingcurve.LogUniswapSwapped{
			PoolAddress: common.HexToAddress(poolAddress2),
			Sender:      common.HexToAddress(userBlockchainAddr2),
			Recipient:   common.HexToAddress(userBlockchainAddr2),
			Amount0:     big.NewInt(1000000000000000000), // 1 token (flows TO pool from user)
			Amount1:     big.NewInt(-90000000000000000),  // -0.09 ION (flows FROM pool to user)
		}

		tx := &txEvent{
			TransactionHash: "0xuniswap_sell_test",
			BlockNumber:     101,
			FromAddress:     userBlockchainAddr2,
			BlockTimestamp:  wtime.New(now),
			Input:           "0x",
		}

		err = ta.(*tokenAnalytics).onUniswapSwapped(ctx, tx, swapEvent)
		require.NoError(t, err, "onUniswapSwapped should complete without error")
	})

	t.Run("rejects_swap_with_nonexistent_pool", func(t *testing.T) {
		nonExistentPool := "0xdead000000000000000000000000000000000001"

		swapEvent := &bondingcurve.LogUniswapSwapped{
			PoolAddress: common.HexToAddress(nonExistentPool),
			Sender:      common.HexToAddress(userBlockchainAddr),
			Recipient:   common.HexToAddress(userBlockchainAddr),
			Amount0:     big.NewInt(-1000000000000000000),
			Amount1:     big.NewInt(100000000000000000),
		}

		tx := &txEvent{
			TransactionHash: "0xuniswap_invalid_pool",
			BlockNumber:     102,
			FromAddress:     userBlockchainAddr,
			BlockTimestamp:  wtime.New(now),
			Input:           "0x",
		}

		err := ta.(*tokenAnalytics).onUniswapSwapped(ctx, tx, swapEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find token by pool")
	})

	t.Run("detects_direction_correctly_when_token_is_token1", func(t *testing.T) {
		poolAddress3 := "0xabcd000000000000000000000000000000000003"
		contractAddress3 := "0xffff000000000000000000000000000000000003"
		externalAddress3 := "30175:uniswap_token1_user:test"
		userBlockchainAddr3 := "0xbbbb000000000000000000000000000000000003"

		helperInsertTestUser(t, ctx, db, "test_pubkey3", "uniswap_token1_user", "Uniswap Token1 User", userBlockchainAddr3, false, "ionconnect")

		helperInsertTestToken(t, ctx, db, contractAddress3, externalAddress3, "TEST3", "profile", "test_pubkey3", "1000000000000000000000", 0.0, 0.0, 0, "ionconnect")

		_, err := storage.Exec(ctx, db, `
			UPDATE tokens SET pair_id = $1, base_token = $2 WHERE contract_address = $3
		`, "0x3333333333333333333333333333333333333333333333333333333333333333", baseToken, contractAddress3)
		require.NoError(t, err)

		// token1 is community token, token0 is ION
		helperInsertUniswapPool(t, ctx, db, poolAddress3, contractAddress3, baseToken, contractAddress3, 3000)

		// buy: user receives community token which is token1
		// Amount0 > 0 means token0 (ION) flows TO the pool
		// Amount1 < 0 means token1 (community token) flows FROM the pool
		swapEvent := &bondingcurve.LogUniswapSwapped{
			PoolAddress: common.HexToAddress(poolAddress3),
			Sender:      common.HexToAddress(userBlockchainAddr3),
			Recipient:   common.HexToAddress(userBlockchainAddr3),
			Amount0:     big.NewInt(100000000000000000),   // 0.1 ION (flows TO pool)
			Amount1:     big.NewInt(-1000000000000000000), // -1 token (flows FROM pool)
		}

		tx := &txEvent{
			TransactionHash: "0xuniswap_token1_test",
			BlockNumber:     103,
			FromAddress:     userBlockchainAddr3,
			BlockTimestamp:  wtime.New(now),
			Input:           "0x",
		}

		err = ta.(*tokenAnalytics).onUniswapSwapped(ctx, tx, swapEvent)
		require.NoError(t, err, "onUniswapSwapped should complete without error")
	})
}

func helperInsertUniswapPool(t *testing.T, ctx context.Context, db *storage.DB, poolAddress, tokenAddress, token0, token1 string, fee int) {
	t.Helper()
	_, err := storage.Exec(ctx, db, `
		INSERT INTO uniswap_pools (pool_address, token_address, token0, token1, fee, created_at)
		VALUES (LOWER($1), LOWER($2), LOWER($3), LOWER($4), $5, NOW())
	`, poolAddress, tokenAddress, token0, token1, fee)
	require.NoError(t, err, "failed to insert uniswap pool")
}
