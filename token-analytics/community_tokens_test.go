// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestGetCommunityTokensByIonConnectAddresses(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ta := &tokenAnalytics{
		ingestedDataDB:  testDB,
		processedDataDB: testRedis,
	}

	t.Run("empty addresses returns empty result", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByIonConnectAddresses(ctx, []string{}, "requestor123")
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("non-existent addresses returns empty result", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByIonConnectAddresses(ctx, []string{"nonexistent:address"}, "requestor123")
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("fetch tokens by ion connect addresses", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator1", "alice", "Alice Creator", "", true, "https://avatar1.png")
		helperInsertTestUser(t, ctx, testDB, "creator2", "bob", "Bob Creator", "", false, "https://avatar2.png")
		helperInsertTestUser(t, ctx, testDB, "requestor123", "charlie", "Charlie", "", false)

		token1ION := "30023:creator1:token1"
		token2ION := "30023:creator2:token2"
		token3ION := "30023:creator1:token3"

		helperInsertTestToken(t, ctx, testDB,
			"0x1111111111111111111111111111111111111111",
			token1ION,
			"TOKEN1",
			"profile",
			"creator1",
			"1000000000000000000000000", // 1M * 1e18
			100.5,                       // market_cap_usd
			0.0001,                      // price_usd
			9,                           // holders_count (will become 10 after user_token_position insert triggers +1)
		)

		helperInsertTestToken(t, ctx, testDB,
			"0x2222222222222222222222222222222222222222",
			token2ION,
			"TOKEN2",
			"post",
			"creator2",
			"5000000000000000000000000", // 5M * 1e18
			500.75,                      // market_cap_usd
			0.0001,                      // price_usd
			25,                          // holders_count
		)

		helperInsertTestToken(t, ctx, testDB,
			"0x3333333333333333333333333333333333333333",
			token3ION,
			"TOKEN3",
			"video",
			"creator1",
			"2000000000000000000000000", // 2M * 1e18
			200.0,                       // market_cap_usd
			0.0001,                      // price_usd
			15,                          // holders_count
		)

		helperInsertUserTokenPosition(t, ctx, testDB,
			"requestor123",
			"0x1111111111111111111111111111111111111111",
			token1ION,
			"500000000000000000000", // 500 * 1e18
			0.00009,                 // avg_buy_price_usd
			45.0,                    // total_invested_usd
		)

		helperInsertTokenSwap(t, ctx, testDB,
			"tx_hash_1",
			"0x1111111111111111111111111111111111111111",
			token1ION,
			"user1",
			false,                    // sell
			"1000000000000000000000", // 1000 * 1e18
			"100000000000000000",     // 0.1 ETH
			0.0001,
		)

		helperInsertTokenSwap(t, ctx, testDB,
			"tx_hash_2",
			"0x2222222222222222222222222222222222222222",
			token2ION,
			"user2",
			false,                    // sell
			"2000000000000000000000", // 2000 * 1e18
			"200000000000000000",     // 0.2 ETH
			0.0001,
		)

		helperSetupRedisPositionData(t, ctx, testRedis.Unwrap(), token1ION, map[string]float64{
			"0:top_holder_1:": 1000.0, // rank 1: 1000 tokens
			"0:top_holder_2:": 750.0,  // rank 2: 750 tokens
			"0:requestor123:": 500.0,  // rank 3: 500 tokens (our user - ion_connect format)
			"0:other_holder:": 250.0,  // rank 4: 250 tokens
		})

		tokens, err := ta.GetCommunityTokensByIonConnectAddresses(ctx,
			[]string{token1ION, token2ION},
			"requestor123", // master_pubkey
		)
		require.NoError(t, err)
		require.Len(t, tokens, 2)

		token1 := helperFindTokenByION(tokens, token1ION)
		require.NotNil(t, token1, "token1 should be found")
		assert.Equal(t, "profile", token1.Type)
		assert.Equal(t, "alice", token1.Title)               // username as title
		assert.Equal(t, "Alice Creator", token1.Description) // display_name as description
		assert.Equal(t, "https://avatar1.png", token1.ImageURL)
		assert.Equal(t, "0x1111111111111111111111111111111111111111", token1.Addresses.Blockchain)
		assert.Equal(t, token1ION, token1.Addresses.IonConnect)

		assert.Equal(t, "alice", token1.Creator.Username)
		assert.Equal(t, "Alice Creator", token1.Creator.Display)
		assert.Equal(t, "https://avatar1.png", token1.Creator.Avatar)
		assert.True(t, token1.Creator.Verified)
		assert.Equal(t, "0:creator1:", token1.Creator.IonConnect)

		assert.Equal(t, "TOKEN1", token1.MarketData.Ticker)
		assert.InDelta(t, 100.5, token1.MarketData.MarketCap, 0.01)
		assert.InDelta(t, 0.0001, token1.MarketData.PriceUSD, 0.000001)
		assert.Equal(t, uint64(10), token1.MarketData.Holders)
		assert.Greater(t, token1.MarketData.Volume, 0.0) // Should have volume from swap

		assert.Equal(t, uint64(3), token1.MarketData.Position.Rank)         // 3rd place
		assert.InDelta(t, 0.05, token1.MarketData.Position.AmountUSD, 0.01) // 500 tokens * 0.0001 = 0.05 USD
		assert.Less(t, token1.MarketData.Position.PnL, 0.0)                 // Should have loss (invested 45, worth 0.05)

		token2 := helperFindTokenByION(tokens, token2ION)
		require.NotNil(t, token2, "token2 should be found")
		assert.Equal(t, "post", token2.Type)
		assert.Equal(t, "bob", token2.Title)
		assert.Equal(t, "Bob Creator", token2.Description)
		assert.False(t, token2.Creator.Verified)
		assert.Equal(t, "TOKEN2", token2.MarketData.Ticker)
		assert.InDelta(t, 500.75, token2.MarketData.MarketCap, 0.01)
		assert.Equal(t, uint64(25), token2.MarketData.Holders)

		assert.Equal(t, uint64(0), token2.MarketData.Position.Rank)
	})

	t.Run("fetch tokens without user positions", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator1_nopos", "alice_nopos", "Alice", "", false)

		token1ION := "30023:creator1_nopos:token1_nopos"
		helperInsertTestToken(t, ctx, testDB,
			"0xaaaa111111111111111111111111111111111111",
			token1ION,
			"TOKEN1",
			"profile",
			"creator1_nopos", // Use correct creator
			"1000000000000000000000000",
			100.0,
			0.0001,
			5,
		)

		tokens, err := ta.GetCommunityTokensByIonConnectAddresses(ctx,
			[]string{token1ION},
			"non_holder_user",
		)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		assert.Equal(t, uint64(0), tokens[0].MarketData.Position.Rank)
		assert.Equal(t, float64(0), tokens[0].MarketData.Position.AmountUSD)
		assert.Equal(t, float64(0), tokens[0].MarketData.Position.PnL)
	})
}

func helperInsertTestUser(t *testing.T, ctx context.Context, db *storage.DB, masterPubkey, username, displayName, blockchainAddr string, verified bool, avatar ...string) {
	t.Helper()
	ionConnectAddr := fmt.Sprintf("0:%s:", masterPubkey) // ion_connect_address format
	if blockchainAddr == "" {
		if len(masterPubkey) >= 40 {
			blockchainAddr = "0x" + masterPubkey[:40]
		} else {
			blockchainAddr = "0x" + masterPubkey + strings.Repeat("0", 40-len(masterPubkey))
		}
	}
	blockchainAddr = strings.ToLower(blockchainAddr)

	avatarURL := "avatar.png"
	if len(avatar) > 0 && avatar[0] != "" {
		avatarURL = avatar[0]
	}

	query := `
		INSERT INTO users (created_at, updated_at, id, master_pubkey, blockchain_address, ion_connect_address, username, display_name, avatar, lookup, verified)
		VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (master_pubkey) DO UPDATE SET
			blockchain_address = EXCLUDED.blockchain_address,
			ion_connect_address = EXCLUDED.ion_connect_address,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			avatar = EXCLUDED.avatar,
			lookup = EXCLUDED.lookup,
			verified = EXCLUDED.verified,
			updated_at = NOW()
	`
	_, err := storage.Exec(ctx, db, query,
		masterPubkey,
		masterPubkey,
		blockchainAddr,
		ionConnectAddr,
		username,
		displayName,
		avatarURL,
		username,
		verified,
	)
	require.NoError(t, err, "failed to insert test user")
}

func helperInsertTestToken(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, ionConnectAddress, ticker, tokenType, creatorPubkey string,
	totalSupply string, marketCapUSD, priceUSD float64, holdersCount int) {
	t.Helper()
	query := `
		INSERT INTO tokens (
			created_at, updated_at, contract_address, ion_connect_address, 
			ticker, total_supply, creator_master_pubkey, type, 
			market_cap_usd, price_usd, holders_count
		)
		VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (ion_connect_address) DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		contractAddress,
		ionConnectAddress,
		ticker,
		totalSupply,
		creatorPubkey,
		tokenType,
		marketCapUSD,
		priceUSD,
		holdersCount,
	)
	require.NoError(t, err, "failed to insert test token")
}

func helperInsertUserTokenPosition(t *testing.T, ctx context.Context, db *storage.DB,
	masterPubkey, contractAddress, ionConnectAddress string, amount string, avgBuyPriceUSD, totalInvestedUSD float64) {
	t.Helper()
	query := `
		INSERT INTO user_token_positions (
			updated_at, master_pubkey, contract_address, ion_connect_address,
			amount, avg_buy_price_usd, total_invested_usd
		)
		VALUES (NOW(), $1, $2, $3, $4, $5, $6)
		ON CONFLICT (master_pubkey, contract_address) DO UPDATE
		SET amount = EXCLUDED.amount,
		    ion_connect_address = EXCLUDED.ion_connect_address,
		    avg_buy_price_usd = EXCLUDED.avg_buy_price_usd,
		    total_invested_usd = EXCLUDED.total_invested_usd,
		    updated_at = NOW()
	`
	_, err := storage.Exec(ctx, db, query,
		masterPubkey,
		contractAddress,
		ionConnectAddress,
		amount,
		avgBuyPriceUSD,
		totalInvestedUSD,
	)
	require.NoError(t, err, "failed to insert user token position")
}

func helperInsertTokenSwap(t *testing.T, ctx context.Context, db *storage.DB,
	txHash, contractAddress, ionConnectAddress, userAddress string,
	direction bool, inputAmount, outputAmount string, priceUSD float64) {
	t.Helper()

	createdAt := time.Now().Add(-1 * time.Hour)

	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, ion_connect_address,
			user_address, direction, input_amount, output_amount, price_usd
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (transaction_hash, contract_address, user_address) DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		createdAt,
		txHash,
		contractAddress,
		ionConnectAddress,
		userAddress,
		direction,
		inputAmount,
		outputAmount,
		priceUSD,
	)
	require.NoError(t, err, "failed to insert token swap")
}

func helperSetupRedisPositionData(t *testing.T, ctx context.Context, client *redis.Client,
	ionConnectAddress string, positions map[string]float64) {
	t.Helper()
	key := keyUserPositionOfToken(ionConnectAddress)

	for masterPubkey, amountUSD := range positions {
		err := client.ZAdd(ctx, key, redis.Z{
			Score:  amountUSD,
			Member: masterPubkey,
		}).Err()
		require.NoError(t, err, "failed to add position to redis")
	}
}

func helperFindTokenByION(tokens []*CommunityToken, ionConnectAddress string) *CommunityToken {
	for _, token := range tokens {
		if token.Addresses.IonConnect == ionConnectAddress {
			return token
		}
	}

	return nil
}

func helperCreateGlobalTopSet(t *testing.T, ctx context.Context, tokens map[string]float64) {
	t.Helper()
	if len(tokens) == 0 {
		return
	}
	members := make([]redis.Z, 0, len(tokens))
	for ionConnect, marketCap := range tokens {
		members = append(members, redis.Z{Score: marketCap, Member: ionConnect})
	}
	err := testRedis.ZAdd(ctx, globalTopSetKey, members...).Err()
	require.NoError(t, err, "failed to create global top set")
}

func helperCreateGlobalTrendingSet(t *testing.T, ctx context.Context, tokens map[string]float64) {
	t.Helper()
	if len(tokens) == 0 {
		return
	}
	members := make([]redis.Z, 0, len(tokens))
	for ionConnect, volume := range tokens {
		members = append(members, redis.Z{Score: volume, Member: ionConnect})
	}
	err := testRedis.ZAdd(ctx, globalTrendingSetKey, members...).Err()
	require.NoError(t, err, "failed to create global trending set")
}

func TestGetCommunityTokensByType(t *testing.T) {
	ctx := t.Context()

	ta := &tokenAnalytics{
		ingestedDataDB:  testDB,
		processedDataDB: testRedis,
	}

	t.Run("returns_latest_tokens", func(t *testing.T) {
		t.Parallel()
		subCtx := t.Context()

		helperInsertTestUser(t, subCtx, testDB, "creator_latest1", "user_latest1", "User Latest 1", "", false)
		helperInsertTestUser(t, subCtx, testDB, "creator_latest2", "user_latest2", "User Latest 2", "", false)
		helperInsertTestToken(t, subCtx, testDB, "0xlatest1", "30023:creator_latest1:token1", "TK1", "profile", "creator_latest1", "1000", 100.0, 0.01, 5)
		helperInsertTestToken(t, subCtx, testDB, "0xlatest2", "30023:creator_latest2:token2", "TK2", "post", "creator_latest2", "2000", 200.0, 0.02, 10)

		tokens, err := ta.GetCommunityTokensByType(subCtx, TokenTypeLatest, "", 10, 0)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 2)

		if len(tokens) >= 2 {
			assert.True(t, tokens[0].CreatedAt.After(tokens[1].CreatedAt) || tokens[0].CreatedAt.Equal(tokens[1].CreatedAt))
		}
	})

	t.Run("filters_by_keyword", func(t *testing.T) {
		t.Parallel()
		subCtx := t.Context()

		helperInsertTestUser(t, subCtx, testDB, "creator_keyword1", "satoshi_test", "Satoshi Test", "", false)
		helperInsertTestUser(t, subCtx, testDB, "creator_keyword2", "vitalik_test", "Vitalik Test", "", false)

		helperInsertTestToken(t, subCtx, testDB, "0xkeyword1", "30023:creator_keyword1:token1", "SAT", "profile", "creator_keyword1", "1000", 100.0, 0.01, 5)
		helperInsertTestToken(t, subCtx, testDB, "0xkeyword2", "30023:creator_keyword2:token2", "VIT", "post", "creator_keyword2", "2000", 200.0, 0.02, 10)

		tokens, err := ta.GetCommunityTokensByType(subCtx, TokenTypeLatest, "satoshi", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, "satoshi_test", tokens[0].Creator.Username)
	})

	t.Run("applies_pagination", func(t *testing.T) {
		t.Parallel()
		subCtx := t.Context()

		for i := 0; i < 5; i++ {
			creator := fmt.Sprintf("creator_page_%d", i)
			helperInsertTestUser(t, subCtx, testDB, creator, creator, creator, "", false)
			helperInsertTestToken(t, subCtx, testDB,
				fmt.Sprintf("0xpage%d", i),
				fmt.Sprintf("30023:%s:token%d", creator, i),
				fmt.Sprintf("TK%d", i),
				"profile",
				creator,
				"1000",
				100.0,
				0.01,
				5,
			)
		}

		tokens, err := ta.GetCommunityTokensByType(subCtx, TokenTypeLatest, "", 2, 0)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens), 2)

		tokens2, err := ta.GetCommunityTokensByType(subCtx, TokenTypeLatest, "", 2, 2)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens2), 2)
	})

	t.Run("returns_error_for_unsupported_type", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByType(ctx, "unsupported_type", "", 10, 0)
		require.Error(t, err)
		assert.Nil(t, tokens)
		assert.Contains(t, err.Error(), "unsupported token type")
	})
}

func TestGetLatestTrades(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	ta := &tokenAnalytics{
		ingestedDataDB:  testDB,
		processedDataDB: testRedis,
	}

	t.Run("returns_latest_trades_for_token", func(t *testing.T) {
		t.Parallel()
		subCtx := t.Context()

		helperInsertTestUser(t, subCtx, testDB, "creator_trades", "trader", "Trader", "", false)
		tokenION := "30023:creator_trades:token_trades"
		helperInsertTestToken(t, subCtx, testDB, "0xtrades1", tokenION, "TRD", "profile", "creator_trades", "1000", 100.0, 0.01, 5)

		helperInsertTokenSwap(t, subCtx, testDB, "tx_trade_1", "0xtrades1", tokenION, "user1", false, "1000", "100", 0.01)
		helperInsertTokenSwap(t, subCtx, testDB, "tx_trade_2", "0xtrades1", tokenION, "user2", true, "500", "50", 0.01)
		helperInsertTokenSwap(t, subCtx, testDB, "tx_trade_3", "0xtrades1", tokenION, "user3", false, "2000", "200", 0.01)

		trades, _, err := ta.GetLatestTrades(subCtx, tokenION, 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(trades), 3)

		assert.Equal(t, tokenION, trades[0].Position.Addresses.IonConnect)
		assert.NotEmpty(t, trades[0].Position.Type)
	})

	t.Run("applies_pagination", func(t *testing.T) {
		t.Parallel()
		subCtx := t.Context()

		helperInsertTestUser(t, subCtx, testDB, "creator_page_trades", "trader_page", "Trader Page", "", false)
		tokenION := "30023:creator_page_trades:token_page_trades"
		helperInsertTestToken(t, subCtx, testDB, "0xpage_trades", tokenION, "TRPG", "profile", "creator_page_trades", "1000", 100.0, 0.01, 5)

		for i := 0; i < 5; i++ {
			helperInsertTokenSwap(t, subCtx, testDB,
				fmt.Sprintf("tx_page_trade_%d", i),
				"0xpage_trades",
				tokenION,
				fmt.Sprintf("user%d", i),
				false,
				"1000",
				"100",
				0.01,
			)
		}

		trades, _, err := ta.GetLatestTrades(subCtx, tokenION, 2, 0, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(trades), 2)

		trades2, _, err := ta.GetLatestTrades(subCtx, tokenION, 2, 2, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(trades2), 2)

		if len(trades) > 0 && len(trades2) > 0 {
			assert.NotEqual(t, trades[0].Position.CreatedAt, trades2[0].Position.CreatedAt)
		}
	})

	t.Run("returns_empty_for_non-existent_token", func(t *testing.T) {
		trades, _, err := ta.GetLatestTrades(ctx, "30023:nonexistent:token", 10, 0, nil)
		require.NoError(t, err)
		require.Empty(t, trades)
	})
}
