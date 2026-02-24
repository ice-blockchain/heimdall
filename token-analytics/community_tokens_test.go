// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestUpdateLoggedInUserProfile_TwoStepUpdate(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("two step update: first profile info, then BSC address", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		xcomUserID := "1234567890123"
		externalAddress := "1234567890123"
		bscWallet := "0xbsc_wallet_address"

		err := ta.UpdateLoggedInUserProfile(
			ctx,
			xcomUserID,
			externalAddress,
			"john_doe",
			"John Doe",
			"https://avatar.com/john.png",
			true,
			"", // empty content_author_id
		)
		require.NoError(t, err)

		type userResult struct {
			ID              string  `db:"id"`
			MasterPubkey    string  `db:"master_pubkey"`
			Username        string  `db:"username"`
			ExternalAddress *string `db:"external_address"`
		}
		result1, err := storage.Get[userResult](ctx, db,
			"SELECT id, master_pubkey, username, external_address FROM users WHERE external_address = $1",
			externalAddress)
		require.NoError(t, err)

		require.Equal(t, "john_doe", result1.Username)
		require.Equal(t, xcomUserID, result1.MasterPubkey)
		require.NotNil(t, result1.ExternalAddress, "external_address should be set")
		require.Equal(t, externalAddress, *result1.ExternalAddress)

		type bscResult struct {
			Count int `db:"count"`
		}
		bscCount, err := storage.Get[bscResult](ctx, db,
			"SELECT COUNT(*) as count FROM user_bsc_addresses WHERE user_id = $1", result1.ID)
		require.NoError(t, err)
		require.Equal(t, 0, bscCount.Count, "should have no bsc addresses initially")

		err = ta.UpdateLoggedInUserProfile(
			ctx,
			externalAddress,
			externalAddress,
			"",
			"",
			"",
			true,
			bscWallet, // content_author_id = BSC wallet
		)
		require.NoError(t, err)

		result2, err := storage.Get[userResult](ctx, db,
			"SELECT id, master_pubkey, username, external_address FROM users WHERE external_address = $1",
			externalAddress)
		require.NoError(t, err)

		require.Equal(t, xcomUserID, result2.MasterPubkey, "master_pubkey should remain X.com user ID (not changed)")
		require.Equal(t, "john_doe", result2.Username, "username should be preserved")
		require.NotNil(t, result2.ExternalAddress, "external_address should be preserved")
		require.Equal(t, externalAddress, *result2.ExternalAddress, "external_address should be preserved")

		type bscAddrResult struct {
			BscAddress string `db:"bsc_address"`
		}
		bscAddr, err := storage.Get[bscAddrResult](ctx, db,
			"SELECT bsc_address FROM user_bsc_addresses WHERE user_id = $1", result2.ID)
		require.NoError(t, err)
		require.Equal(t, strings.ToLower(bscWallet), bscAddr.BscAddress, "bsc_address should be stored in user_bsc_addresses")

		type countResult struct {
			Count int `db:"count"`
		}
		countRes, err := storage.Get[countResult](ctx, db, "SELECT COUNT(*) as count FROM users WHERE external_address = $1", externalAddress)
		require.NoError(t, err)
		require.Equal(t, 1, countRes.Count, "should have exactly 1 user")
	})
}

func TestUpdateLoggedInUserProfile(t *testing.T) {
	t.Parallel()

	t.Run("creates new user with all data in single call", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		xcomUserID := "9876543210"
		externalAddress := "9876543210"
		bscWallet := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"

		err := ta.UpdateLoggedInUserProfile(
			ctx,
			xcomUserID,
			externalAddress,
			"alice",
			"Alice Wonder",
			"https://avatar.com/alice.png",
			true,
			bscWallet,
		)
		require.NoError(t, err)

		type userResult struct {
			ID              string `db:"id"`
			MasterPubkey    string `db:"master_pubkey"`
			Username        string `db:"username"`
			DisplayName     string `db:"display_name"`
			ExternalAddress string `db:"external_address"`
			PlatformGroup   string `db:"platform_group"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT id, master_pubkey, username, display_name, external_address, platform_group FROM users WHERE external_address = $1",
			externalAddress)
		require.NoError(t, err)
		require.Equal(t, xcomUserID, user.MasterPubkey)
		require.Equal(t, "alice", user.Username)
		require.Equal(t, "Alice Wonder", user.DisplayName)
		require.Equal(t, externalAddress, user.ExternalAddress)
		require.Equal(t, PlatformGroupXCom, user.PlatformGroup)

		type bscAddrResult struct {
			BscAddress string `db:"bsc_address"`
		}
		bscAddr, err := storage.Get[bscAddrResult](ctx, db,
			"SELECT bsc_address FROM user_bsc_addresses WHERE user_id = $1", user.ID)
		require.NoError(t, err)
		require.Equal(t, strings.ToLower(bscWallet), bscAddr.BscAddress)
	})

	t.Run("updates existing user profile fields", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		xcomUserID := "5555555555"
		externalAddress := "5555555555"
		bscWallet := "0x1111111111111111111111111111111111111111"

		err := ta.UpdateLoggedInUserProfile(ctx, xcomUserID, externalAddress, "bob", "Bob Builder", "", true, bscWallet)
		require.NoError(t, err)

		err = ta.UpdateLoggedInUserProfile(ctx, xcomUserID, externalAddress, "bob_updated", "Bob The Builder", "https://new-avatar.com/bob.png", false, bscWallet)
		require.NoError(t, err, "idempotent call should not fail")

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
			Verified    bool    `db:"verified"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT username, display_name, avatar, verified FROM users WHERE external_address = $1",
			externalAddress)
		require.NoError(t, err)
		require.Equal(t, "bob_updated", user.Username)
		require.Equal(t, "Bob The Builder", user.DisplayName)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "https://new-avatar.com/bob.png", *user.Avatar)
		require.Equal(t, false, user.Verified)
	})

	t.Run("adds second BSC address to existing user", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		xcomUserID := "7777777777"
		externalAddress := "7777777777"
		bscWallet1 := "0x2222222222222222222222222222222222222222"
		bscWallet2 := "0x3333333333333333333333333333333333333333"

		err := ta.UpdateLoggedInUserProfile(ctx, xcomUserID, externalAddress, "charlie", "Charlie", "", true, bscWallet1)
		require.NoError(t, err)

		err = ta.UpdateLoggedInUserProfile(ctx, xcomUserID, externalAddress, "", "", "", true, bscWallet2)
		require.NoError(t, err)

		type userResult struct {
			ID string `db:"id"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT id FROM users WHERE external_address = $1", externalAddress)
		require.NoError(t, err)

		type bscAddrResult struct {
			BscAddress string `db:"bsc_address"`
		}
		bscAddrs, err := storage.Select[bscAddrResult](ctx, db,
			"SELECT bsc_address FROM user_bsc_addresses WHERE user_id = $1 ORDER BY bsc_address", user.ID)
		require.NoError(t, err)
		require.Equal(t, 2, len(bscAddrs), "should have 2 BSC addresses")
		require.Equal(t, strings.ToLower(bscWallet1), bscAddrs[0].BscAddress)
		require.Equal(t, strings.ToLower(bscWallet2), bscAddrs[1].BscAddress)
	})

	t.Run("silently ignores BSC address when already exists for another user", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		bscWallet := "0x4444444444444444444444444444444444444444"

		err := ta.UpdateLoggedInUserProfile(ctx, "user1_master", "ext_addr_1", "user1", "User 1", "", true, bscWallet)
		require.NoError(t, err)

		err = ta.UpdateLoggedInUserProfile(ctx, "user2_master", "ext_addr_2", "user2", "User 2", "", true, bscWallet)
		require.NoError(t, err, "should not return error, silently ignores duplicate BSC")

		type userBSCResult struct {
			UserID     string  `db:"user_id"`
			BSCAddress *string `db:"bsc_address"`
		}

		user1, err := storage.Get[userBSCResult](ctx, db, `
			SELECT u.id as user_id, uba.bsc_address
			FROM users u
			LEFT JOIN user_bsc_addresses uba ON u.id = uba.user_id
			WHERE u.external_address = $1
		`, "ext_addr_1")
		require.NoError(t, err)
		require.NotNil(t, user1.BSCAddress)
		require.Equal(t, strings.ToLower(bscWallet), *user1.BSCAddress)

		user2, err := storage.Get[userBSCResult](ctx, db, `
			SELECT u.id as user_id, uba.bsc_address
			FROM users u
			LEFT JOIN user_bsc_addresses uba ON u.id = uba.user_id
			WHERE u.external_address = $1
		`, "ext_addr_2")
		require.NoError(t, err)
		require.Nil(t, user2.BSCAddress, "user2 should have no BSC address")
	})

	t.Run("idempotent: calling with same BSC address does not create duplicates", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		xcomUserID := "8888888888"
		externalAddress := "8888888888"
		bscWallet := "0x5555555555555555555555555555555555555555"

		err := ta.UpdateLoggedInUserProfile(ctx, xcomUserID, externalAddress, "dave", "Dave", "", true, bscWallet)
		require.NoError(t, err)

		err = ta.UpdateLoggedInUserProfile(ctx, xcomUserID, externalAddress, "dave", "Dave", "", true, bscWallet)
		require.NoError(t, err, "idempotent call should not fail")

		type userResult struct {
			ID string `db:"id"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT id FROM users WHERE external_address = $1", externalAddress)
		require.NoError(t, err)

		type bscResult struct {
			Count int `db:"count"`
		}
		bscCount, err := storage.Get[bscResult](ctx, db,
			"SELECT COUNT(*) as count FROM user_bsc_addresses WHERE user_id = $1", user.ID)
		require.NoError(t, err)
		require.Equal(t, 1, bscCount.Count, "should have exactly 1 BSC address despite 2 calls")
	})
}

func TestCalculatePnL(t *testing.T) {
	t.Parallel()

	t.Run("profit scenario", func(t *testing.T) {
		// Invested $100, paid $2 in fees (2% on buy), current value $150, no sales
		// PnL = 150 + 0 - 100 + 2 = $52
		pnl, pnlPercentage := calculatePnL(150.0, 100.0, 0.0, 2.0)
		require.InDelta(t, 52.0, pnl, 0.01, "PnL should be $52")
		require.InDelta(t, 52.0, pnlPercentage, 0.01, "PnL% should be 52%")
	})

	t.Run("loss scenario", func(t *testing.T) {
		// Invested $100, paid $2 in fees (2% on buy), current value $80, no sales
		// PnL = 80 + 0 - 100 + 2 = -$18
		pnl, pnlPercentage := calculatePnL(80.0, 100.0, 0.0, 2.0)
		require.InDelta(t, -18.0, pnl, 0.01, "PnL should be -$18")
		require.InDelta(t, -18.0, pnlPercentage, 0.01, "PnL% should be -18%")
	})

	t.Run("break even with partial sale - your example", func(t *testing.T) {
		// Bought 100 ION worth ($0.3), fee $0.006 (2%)
		// Bought 200 ION worth ($0.6), fee $0.012 (2%)
		// Total invested: $0.9, total fees: $0.018
		// Sold 50% (450 tokens) for 150 ION ($0.45), fee $0.009 (2%) - realized $0.45
		// Holding 50% (450 tokens) worth $0.45 - unrealized $0.45
		// Total fees: $0.018 + $0.009 = $0.027
		// PnL = 0.45 + 0.45 - 0.9 + 0.027 = $0.027

		invested := 0.9
		currentHoldingValue := 0.45
		realized := 0.45
		fees := 0.027

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized, fees)
		require.InDelta(t, 0.027, pnl, 0.01, "PnL should be $0.027 (fees recovered)")
		require.InDelta(t, 3.0, pnlPercentage, 0.5, "PnL% should be ~3%")
	})

	t.Run("profit with partial sale", func(t *testing.T) {
		// Invested $100, paid $2 in fees on buy (2%)
		// Sold 50% for $60, paid $1.2 in fees on sell (2% of $60)
		// Holding 50% worth $55 (unrealized profit)
		// Total fees: $2 + $1.2 = $3.2
		// PnL = 55 + 60 - 100 + 3.2 = $18.2

		invested := 100.0
		currentHoldingValue := 55.0
		realized := 60.0
		fees := 3.2

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized, fees)
		require.InDelta(t, 18.2, pnl, 0.01, "PnL should be $18.2")
		require.InDelta(t, 18.2, pnlPercentage, 0.01, "PnL% should be 18.2%")
	})

	t.Run("loss with partial sale", func(t *testing.T) {
		// Invested $100, paid $2 in fees on buy (2%)
		// Sold 50% for $40, paid $0.8 in fees on sell (2% of $40)
		// Holding 50% worth $35 (unrealized loss)
		// Total fees: $2 + $0.8 = $2.8
		// PnL = 35 + 40 - 100 + 2.8 = -$22.2

		invested := 100.0
		currentHoldingValue := 35.0
		realized := 40.0
		fees := 2.8

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized, fees)
		require.InDelta(t, -22.2, pnl, 0.01, "PnL should be -$22.2")
		require.InDelta(t, -22.2, pnlPercentage, 0.01, "PnL% should be -22.2%")
	})

	t.Run("sold everything at profit", func(t *testing.T) {
		// Invested $100, paid $2 in fees on buy (2%)
		// Sold everything for $120, paid $2.4 in fees on sell (2% of $120)
		// Current holding: $0, realized: $120
		// Total fees: $2 + $2.4 = $4.4
		// PnL = 0 + 120 - 100 + 4.4 = $24.4

		invested := 100.0
		currentHoldingValue := 0.0
		realized := 120.0
		fees := 4.4

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized, fees)
		require.InDelta(t, 24.4, pnl, 0.01, "PnL should be $24.4")
		require.InDelta(t, 24.4, pnlPercentage, 0.01, "PnL% should be 24.4%")
	})

	t.Run("sold everything at loss", func(t *testing.T) {
		// Invested $100, paid $2 in fees on buy (2%)
		// Sold everything for $70, paid $1.4 in fees on sell (2% of $70)
		// Current holding: $0, realized: $70
		// Total fees: $2 + $1.4 = $3.4
		// PnL = 0 + 70 - 100 + 3.4 = -$26.6

		invested := 100.0
		currentHoldingValue := 0.0
		realized := 70.0
		fees := 3.4

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized, fees)
		require.InDelta(t, -26.6, pnl, 0.01, "PnL should be -$26.6")
		require.InDelta(t, -26.6, pnlPercentage, 0.01, "PnL% should be -26.6%")
	})

	t.Run("handles zero investment", func(t *testing.T) {
		// Edge case: somehow got tokens without investment (airdrop?)
		pnl, pnlPercentage := calculatePnL(100.0, 0.0, 0.0, 0.0)
		require.Equal(t, 100.0, pnl, "PnL should equal current value")
		require.Equal(t, 0.0, pnlPercentage, "PnL% should be 0 when invested is 0")
	})

	t.Run("doubled investment", func(t *testing.T) {
		// Invested $100, paid $2 in fees on buy (2%), now worth $200 (all unrealized)
		// PnL = 200 + 0 - 100 + 2 = $102
		pnl, pnlPercentage := calculatePnL(200.0, 100.0, 0.0, 2.0)
		require.InDelta(t, 102.0, pnl, 0.01, "PnL should be $102")
		require.InDelta(t, 102.0, pnlPercentage, 0.01, "PnL% should be 102%")
	})

	t.Run("round-trip with fees at constant price", func(t *testing.T) {
		// Buy: input=100 ION, fee=2 ION (2%), output=98 tokens
		// Sell: input=98 tokens, fee=1.96 ION (2% of 98), output=96.04 ION
		// At constant price: invested=$100, realized=$96.04, fees=$2 + $1.96 = $3.96
		// PnL = 0 + 96.04 - 100 + 3.96 = 0
		invested := 100.0
		currentHoldingValue := 0.0
		realized := 96.04
		fees := 3.96

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized, fees)
		require.InDelta(t, 0.0, pnl, 0.01, "PnL should be $0 for round-trip at constant price")
		require.InDelta(t, 0.0, pnlPercentage, 0.01, "PnL% should be 0%")
	})
}

func TestDetermineBaseTokenFromExternalAddress(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, release := helperCreateDB(t)
	defer release()

	taImpl := helperNewForTest(t, db, WithoutQuestDB())

	t.Run("xcom_numeric_id_returns_ion", func(t *testing.T) {
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, "1234567890")

		require.NoError(t, err)
		require.Equal(t, taImpl.cfg.IONTokenAddress, baseToken)
	})

	t.Run("online_plus_creator_token_returns_ion", func(t *testing.T) {
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, "0:testcreatorpubkey123:")

		require.NoError(t, err)
		require.Equal(t, taImpl.cfg.IONTokenAddress, baseToken)
	})

	t.Run("online_plus_content_token_creator_exists", func(t *testing.T) {
		creatorPubkey := "creator_test1_abc123"
		creatorExternalAddr := BuildProfileExternalAddress(creatorPubkey)
		creatorContractAddr := "0x5555555555555555555555555555555555555551"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator1", "Creator 1", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, creatorContractAddr, creatorExternalAddr, "CREA1", "profile", creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)

		contentExternalAddr := "30175:" + creatorPubkey + ":post123"
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, contentExternalAddr)

		require.NoError(t, err)
		require.Equal(t, creatorContractAddr, baseToken)
	})

	t.Run("online_plus_content_token_creator_not_exists", func(t *testing.T) {
		contentExternalAddr := "30175:nonexistent_creator_xyz:post456"
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, contentExternalAddr)

		require.Error(t, err, storage.ErrNotFound)
		require.Equal(t, taImpl.cfg.IONTokenAddress, baseToken, "Should fallback to ION when creator token not found")
	})

	t.Run("online_plus_article_token", func(t *testing.T) {
		creatorPubkey := "creator_test2_def456"
		creatorExternalAddr := BuildProfileExternalAddress(creatorPubkey)
		creatorContractAddr := "0x6666666666666666666666666666666666666662"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator2", "Creator 2", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, creatorContractAddr, creatorExternalAddr, "CREA2", "profile", creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)

		articleExternalAddr := "30023:" + creatorPubkey + ":article789"
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, articleExternalAddr)

		require.NoError(t, err)
		require.Equal(t, creatorContractAddr, baseToken)
	})

	t.Run("invalid_format_single_colon", func(t *testing.T) {
		_, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, ":")

		require.Error(t, err)
	})

	t.Run("content_token_with_empty_creator_pubkey", func(t *testing.T) {
		contentExternalAddr := "30175::post999"
		_, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, contentExternalAddr)

		require.Error(t, err)
	})

	t.Run("creator_token_with_trailing_identifier", func(t *testing.T) {
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, "0:somepubkey:creator")

		require.NoError(t, err)
		require.Equal(t, taImpl.cfg.IONTokenAddress, baseToken)
	})

	t.Run("mixed_case_handling", func(t *testing.T) {
		creatorPubkey := "MixedCasePubkey123Test4"
		creatorExternalAddr := BuildProfileExternalAddress(creatorPubkey)
		creatorContractAddr := "0x8888888888888888888888888888888888888884"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator4", "Creator 4", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, creatorContractAddr, creatorExternalAddr, "CREA4", "profile", creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)

		contentExternalAddr := "30175:" + creatorPubkey + ":content"
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, contentExternalAddr)

		require.NoError(t, err)
		require.Equal(t, creatorContractAddr, baseToken)
	})

	t.Run("multiple_colons_in_content_id", func(t *testing.T) {
		creatorPubkey := fmt.Sprintf("creator_multicolon_test5_%d", 12345)
		creatorExternalAddr := BuildProfileExternalAddress(creatorPubkey)
		creatorContractAddr := "0x9999999999999999999999999999999999999995"

		helperInsertTestUser(t, ctx, db, creatorPubkey, "creator5", "Creator 5", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, creatorContractAddr, creatorExternalAddr, "CREA5", "profile", creatorPubkey, "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)

		contentExternalAddr := "30175:" + creatorPubkey + ":content:with:many:colons"
		baseToken, _, err := determineBaseTokenFromExternalAddress(ctx, taImpl.cfg, taImpl.ingestedDataDB, contentExternalAddr)

		require.NoError(t, err)
		require.Equal(t, creatorContractAddr, baseToken)
	})
}

func TestUpdateTokenExternalData(t *testing.T) {
	t.Parallel()

	t.Run("creates pending token with user and BSC address", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		mockIdentitySvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"address": "nostr:mock_ion_address"}) //nolint:errcheck // test
		}))
		defer mockIdentitySvc.Close()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ta.identityClient = newIdentityClient(mockIdentitySvc.URL, "test-api-key")
		ctx := context.Background()

		tokenExternalAddress := "token_ext_1"
		postAuthorExternalAddress := "author_ext_1"
		userContentId := "0xAUTHOR_BSC_ADDRESS_1"
		tokenImageUrl := "https://example.com/token1.png"

		err := ta.UpdateTokenExternalData(
			ctx,
			tokenExternalAddress,
			postAuthorExternalAddress,
			"author1",
			"Author One",
			"https://example.com/author1.png",
			true,
			userContentId,
			tokenImageUrl,
		)
		require.NoError(t, err)

		type userResult struct {
			ID              string `db:"id"`
			MasterPubkey    string `db:"master_pubkey"`
			ExternalAddress string `db:"external_address"`
			Username        string `db:"username"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT id, master_pubkey, external_address, username FROM users WHERE external_address = $1",
			postAuthorExternalAddress)
		require.NoError(t, err)
		require.Equal(t, postAuthorExternalAddress, user.MasterPubkey)
		require.Equal(t, postAuthorExternalAddress, user.ExternalAddress)
		require.Equal(t, "author1", user.Username)

		type bscAddrResult struct {
			BscAddress string `db:"bsc_address"`
		}
		bscAddr, err := storage.Get[bscAddrResult](ctx, db,
			"SELECT bsc_address FROM user_bsc_addresses WHERE user_id = $1", user.ID)
		require.NoError(t, err)
		require.Equal(t, strings.ToLower(userContentId), bscAddr.BscAddress)

		type tokenResult struct {
			ExternalAddress string  `db:"external_address"`
			ContractAddress *string `db:"contract_address"`
			ContentAuthorId *string `db:"content_author_id"`
			ImageUrl        *string `db:"image_url"`
			IonConnectAddr  *string `db:"ion_connect_address"`
			Platform        string  `db:"platform"`
			Type            string  `db:"type"`
		}
		token, err := storage.Get[tokenResult](ctx, db,
			"SELECT external_address, contract_address, content_author_id, image_url, ion_connect_address, platform, type FROM tokens WHERE external_address = $1",
			tokenExternalAddress)
		require.NoError(t, err)
		require.Equal(t, tokenExternalAddress, token.ExternalAddress)
		require.Nil(t, token.ContractAddress, "contract_address should be NULL for pending token")
		require.NotNil(t, token.ContentAuthorId)
		require.Equal(t, strings.ToLower(userContentId), *token.ContentAuthorId)
		require.NotNil(t, token.ImageUrl)
		require.Equal(t, tokenImageUrl, *token.ImageUrl)
		require.Equal(t, PlatformGroupXCom, token.Platform)
		require.Equal(t, "post", token.Type)
	})

	t.Run("updates existing token with new image", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		mockIdentitySvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"address": "nostr:mock_ion_address"}) //nolint:errcheck // test
		}))
		defer mockIdentitySvc.Close()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ta.identityClient = newIdentityClient(mockIdentitySvc.URL, "test-api-key")
		ctx := context.Background()

		tokenExternalAddress := "token_ext_2"
		postAuthorExternalAddress := "author_ext_2"
		userContentId := "0xAUTHOR_BSC_ADDRESS_2"

		err := ta.UpdateTokenExternalData(ctx, tokenExternalAddress, postAuthorExternalAddress, "author2", "Author Two", "", true, userContentId, "https://old-image.com/token2.png")
		require.NoError(t, err)

		newImage := "https://new-image.com/token2.png"
		err = ta.UpdateTokenExternalData(ctx, tokenExternalAddress, postAuthorExternalAddress, "author2", "Author Two", "", true, userContentId, newImage)
		require.NoError(t, err)

		type tokenResult struct {
			ImageUrl *string `db:"image_url"`
		}
		token, err := storage.Get[tokenResult](ctx, db,
			"SELECT image_url FROM tokens WHERE external_address = $1", tokenExternalAddress)
		require.NoError(t, err)
		require.NotNil(t, token.ImageUrl)
		require.Equal(t, newImage, *token.ImageUrl)
	})

	t.Run("creates token without BSC address (pending)", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		mockIdentitySvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"address": "nostr:mock_ion_address"}) //nolint:errcheck // test
		}))
		defer mockIdentitySvc.Close()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ta.identityClient = newIdentityClient(mockIdentitySvc.URL, "test-api-key")
		ctx := context.Background()

		tokenExternalAddress := "token_ext_pending"
		postAuthorExternalAddress := "author_ext_pending"

		err := ta.UpdateTokenExternalData(
			ctx,
			tokenExternalAddress,
			postAuthorExternalAddress,
			"author_pending",
			"Author Pending",
			"",
			true,
			"", // empty userContentId
			"https://example.com/pending.png",
		)
		require.NoError(t, err)

		type tokenResult struct {
			ExternalAddress string  `db:"external_address"`
			ContentAuthorId *string `db:"content_author_id"`
		}
		token, err := storage.Get[tokenResult](ctx, db,
			"SELECT external_address, content_author_id FROM tokens WHERE external_address = $1",
			tokenExternalAddress)
		require.NoError(t, err)
		require.Equal(t, tokenExternalAddress, token.ExternalAddress)
		require.Nil(t, token.ContentAuthorId, "content_author_id should be NULL when userContentId is empty")

		type userResult struct {
			ID string `db:"id"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT id FROM users WHERE external_address = $1", postAuthorExternalAddress)
		require.NoError(t, err)

		type bscResult struct {
			Count int `db:"count"`
		}
		bscCount, err := storage.Get[bscResult](ctx, db,
			"SELECT COUNT(*) as count FROM user_bsc_addresses WHERE user_id = $1", user.ID)
		require.NoError(t, err)
		require.Equal(t, 0, bscCount.Count, "should have no BSC addresses when userContentId is empty")
	})

	t.Run("silently ignores BSC address when already exists for another user", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		mockIdentitySvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"address": "nostr:mock_ion_address"}) //nolint:errcheck // test
		}))
		defer mockIdentitySvc.Close()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ta.identityClient = newIdentityClient(mockIdentitySvc.URL, "test-api-key")
		ctx := context.Background()

		sharedBSC := "0xSHARED_BSC_ADDRESS"
		err := ta.UpdateTokenExternalData(ctx, "token_ext_user1", "author_ext_1", "author1", "Author 1", "", true, sharedBSC, "https://img1.png")
		require.NoError(t, err)

		err = ta.UpdateTokenExternalData(ctx, "token_ext_user2", "author_ext_2", "author2", "Author 2", "", true, sharedBSC, "https://img2.png")
		require.NoError(t, err, "should not return error, silently ignores duplicate BSC")

		type userBSC struct {
			UserID     string  `db:"user_id"`
			BSCAddress *string `db:"bsc_address"`
		}

		user1, err := storage.Get[userBSC](ctx, db, `
			SELECT u.id as user_id, uba.bsc_address
			FROM users u
			LEFT JOIN user_bsc_addresses uba ON u.id = uba.user_id
			WHERE u.external_address = $1
		`, "author_ext_1")
		require.NoError(t, err)
		require.NotNil(t, user1.BSCAddress)
		require.Equal(t, strings.ToLower(sharedBSC), *user1.BSCAddress)

		user2, err := storage.Get[userBSC](ctx, db, `
			SELECT u.id as user_id, uba.bsc_address
			FROM users u
			LEFT JOIN user_bsc_addresses uba ON u.id = uba.user_id
			WHERE u.external_address = $1
		`, "author_ext_2")
		require.NoError(t, err)
		require.Nil(t, user2.BSCAddress, "user2 should have no BSC address")
	})

	t.Run("updates user profile when called multiple times", func(t *testing.T) {
		t.Parallel()
		db, release := helperCreateDB(t)
		defer release()

		mockIdentitySvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"address": "nostr:mock_ion_address"}) //nolint:errcheck // test
		}))
		defer mockIdentitySvc.Close()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ta.identityClient = newIdentityClient(mockIdentitySvc.URL, "test-api-key")
		ctx := context.Background()

		tokenExternalAddress := "token_ext_3"
		postAuthorExternalAddress := "author_ext_3"
		userContentId := "0xAUTHOR_BSC_ADDRESS_3"

		err := ta.UpdateTokenExternalData(ctx, tokenExternalAddress, postAuthorExternalAddress, "old_name", "Old Name", "", false, userContentId, "")
		require.NoError(t, err)

		err = ta.UpdateTokenExternalData(ctx, tokenExternalAddress, postAuthorExternalAddress, "new_name", "New Name", "https://new-avatar.com/author.png", true, userContentId, "")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
			Verified    bool    `db:"verified"`
		}
		user, err := storage.Get[userResult](ctx, db,
			"SELECT username, display_name, avatar, verified FROM users WHERE external_address = $1",
			postAuthorExternalAddress)
		require.NoError(t, err)
		require.Equal(t, "new_name", user.Username)
		require.Equal(t, "New Name", user.DisplayName)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "https://new-avatar.com/author.png", *user.Avatar)
		require.Equal(t, true, user.Verified)
	})
}
