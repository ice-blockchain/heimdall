// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestUpdateUserProfileAndToken(t *testing.T) {
	t.Skip("Skipping this test for now due to us not returning an error when updating user profile and token")
	t.Parallel()

	t.Run("updates user and profile token when username changes", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_1"
		profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

		helperInsertTestUser(t, t.Context(), db, masterPubkey, "oldusername", "Old Display", masterPubkey, false, PlatformGroupIonConnect, "old_avatar.jpg")
		helperInsertTestToken(t, t.Context(), db, "0x1111111111111111111111111111111111111111", profileExternalAddr, "oldusername", "profile", masterPubkey, "1000000000000000000000000000", 0, 0, 1, PlatformGroupIonConnect)
		tcCoin, err := ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "newusername", "New Display", "new_avatar.jpg")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT username, display_name, avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.Equal(t, "newusername", user.Username)
		require.Equal(t, "New Display", user.DisplayName)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "new_avatar.jpg", *user.Avatar)
		type tokenResult struct {
			Ticker   string  `db:"ticker"`
			Title    string  `db:"title"`
			ImageURL *string `db:"image_url"`
		}
		token, err := storage.Get[tokenResult](t.Context(), db, `SELECT ticker, title, image_url FROM tokens WHERE external_address = $1 AND type = 'profile'`, profileExternalAddr)
		require.NoError(t, err)
		require.Equal(t, "newusername", token.Ticker)
		require.Equal(t, tcCoin.Symbol(), token.Ticker)
		require.Equal(t, tcCoin.Name(), token.Title)
		require.NotNil(t, token.ImageURL)
		require.Equal(t, "new_avatar.jpg", *token.ImageURL)
		require.Equal(t, tcCoin.IconUrl(), *token.ImageURL)
	})

	t.Run("updates user and profile token when display name changes", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_2"
		profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

		helperInsertTestUser(t, t.Context(), db, masterPubkey, "username", "Old Display", masterPubkey, false, PlatformGroupIonConnect, "avatar.jpg")
		helperInsertTestToken(t, t.Context(), db, "0x3333333333333333333333333333333333333333", profileExternalAddr, "username", "profile", masterPubkey, "1000000000000000000000000000", 0, 0, 1, PlatformGroupIonConnect)
		tcCoin, err := ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "username", "New Display Name", "avatar.jpg")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT username, display_name, avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.Equal(t, "username", user.Username)
		require.Equal(t, "New Display Name", user.DisplayName)

		type tokenResult struct {
			Ticker   string  `db:"ticker"`
			Title    string  `db:"title"`
			ImageURL *string `db:"image_url"`
		}
		token, err := storage.Get[tokenResult](t.Context(), db, `SELECT ticker, title, image_url FROM tokens WHERE external_address = $1 AND type = 'profile'`, profileExternalAddr)
		require.NoError(t, err)
		require.Equal(t, "username", token.Ticker)
		require.Equal(t, "username", tcCoin.Symbol())
		require.Equal(t, "New Display Name", token.Title)
		require.Equal(t, "New Display Name", tcCoin.Name())
	})

	t.Run("updates user and profile token when avatar changes", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_3"
		profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

		helperInsertTestUser(t, t.Context(), db, masterPubkey, "username", "Display Name", masterPubkey, false, PlatformGroupIonConnect, "old_avatar.jpg")
		helperInsertTestToken(t, t.Context(), db, "0x5555555555555555555555555555555555555555", profileExternalAddr, "username", "profile", masterPubkey, "1000000000000000000000000000", 0, 0, 1, PlatformGroupIonConnect)
		tcCoin, err := ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "username", "Display Name", "new_avatar.jpg")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT username, display_name, avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "new_avatar.jpg", *user.Avatar)

		type tokenResult struct {
			Ticker   string  `db:"ticker"`
			Title    string  `db:"title"`
			ImageURL *string `db:"image_url"`
		}
		token, err := storage.Get[tokenResult](t.Context(), db, `SELECT ticker, title, image_url FROM tokens WHERE external_address = $1 AND type = 'profile'`, profileExternalAddr)
		require.NoError(t, err)
		require.NotNil(t, token.ImageURL)
		require.NotNil(t, tcCoin)
		require.Equal(t, "new_avatar.jpg", *token.ImageURL)
		require.Equal(t, "new_avatar.jpg", tcCoin.IconUrl())
	})

	t.Run("updates user but not profile token when no changes", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_4"
		profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

		helperInsertTestUser(t, t.Context(), db, masterPubkey, "username", "Display Name", masterPubkey, false, PlatformGroupIonConnect, "avatar.jpg")
		helperInsertTestToken(t, t.Context(), db, "0x7777777777777777777777777777777777777777", profileExternalAddr, "username", "profile", masterPubkey, "1000000000000000000000000000", 0, 0, 1, PlatformGroupIonConnect)
		_, err := storage.Exec(t.Context(), db, `UPDATE tokens SET ticker = $1, title = $2, image_url = $3 WHERE external_address = $4`, "username", "Display Name", "avatar.jpg", profileExternalAddr)
		require.NoError(t, err)

		_, err = ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "username", "Display Name", "avatar.jpg")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT username, display_name, avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.Equal(t, "username", user.Username)
		require.Equal(t, "Display Name", user.DisplayName)
	})

	t.Run("updates user even when profile token does not exist", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_5"

		helperInsertTestUser(t, t.Context(), db, masterPubkey, "oldusername", "Old Display", masterPubkey, false, PlatformGroupIonConnect, "old_avatar.jpg")

		_, err := ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "newusername", "New Display", "new_avatar.jpg")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT username, display_name, avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.Equal(t, "newusername", user.Username)
		require.Equal(t, "New Display", user.DisplayName)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "new_avatar.jpg", *user.Avatar)
	})

	t.Run("handles empty avatar string correctly", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_6"
		profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

		helperInsertTestUser(t, t.Context(), db, masterPubkey, "username", "Display Name", masterPubkey, false, PlatformGroupIonConnect, "old_avatar.jpg")

		helperInsertTestToken(t, t.Context(), db, "0x9999999999999999999999999999999999999999", profileExternalAddr, "username", "profile", masterPubkey, "1000000000000000000000000000", 0, 0, 1, PlatformGroupIonConnect)
		_, err := storage.Exec(t.Context(), db, `UPDATE tokens SET ticker = $1, title = $2, image_url = $3 WHERE external_address = $4`, "username", "Display Name", "old_avatar.jpg", profileExternalAddr)
		require.NoError(t, err)

		_, err = ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "username", "Display Name", "")
		require.NoError(t, err)

		type userResult struct {
			Username    string  `db:"username"`
			DisplayName string  `db:"display_name"`
			Avatar      *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT username, display_name, avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "old_avatar.jpg", *user.Avatar, "avatar should remain unchanged when empty string is passed")

		type tokenResult struct {
			ImageURL *string `db:"image_url"`
		}
		token, err := storage.Get[tokenResult](t.Context(), db, `SELECT image_url FROM tokens WHERE external_address = $1 AND type = 'profile'`, profileExternalAddr)
		require.NoError(t, err)
		require.NotNil(t, token.ImageURL)
		require.Equal(t, "old_avatar.jpg", *token.ImageURL, "token image_url should remain unchanged when empty string is passed")
	})

	t.Run("handles NULL to non-NULL avatar transition", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := &tokenAnalyticsUsers{ingestedDataDB: db}

		masterPubkey := "test_master_pubkey_7"
		profileExternalAddr := BuildProfileExternalAddress(masterPubkey)

		_, err := storage.Exec(t.Context(), db, `
			WITH ins_user AS (
				INSERT INTO users (id, master_pubkey, external_address, username, display_name, avatar, platform_group, lookup, created_at, updated_at)
				VALUES ($1, $1, $2, $3, $4, NULL, $5, LOWER(TRIM($3 || ' ' || $4)), NOW(), NOW())
				RETURNING id
			)
			INSERT INTO user_bsc_addresses (user_id, bsc_address, created_at)
			SELECT id, LOWER($2), NOW() FROM ins_user
			ON CONFLICT (bsc_address) DO NOTHING
		`, masterPubkey, masterPubkey, "username", "Display Name", PlatformGroupIonConnect)
		require.NoError(t, err)

		helperInsertTestToken(t, t.Context(), db, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", profileExternalAddr, "username", "profile", masterPubkey, "1000000000000000000000000000", 0, 0, 1, PlatformGroupIonConnect)

		_, err = ta.UpdateUserProfileAndToken(t.Context(), masterPubkey, "username", "Display Name", "new_avatar.jpg")
		require.NoError(t, err)

		type userResult struct {
			Avatar *string `db:"avatar"`
		}
		user, err := storage.Get[userResult](t.Context(), db, `SELECT avatar FROM users WHERE master_pubkey = $1`, masterPubkey)
		require.NoError(t, err)
		require.NotNil(t, user.Avatar)
		require.Equal(t, "new_avatar.jpg", *user.Avatar)

		type tokenResult struct {
			ImageURL *string `db:"image_url"`
		}
		token, err := storage.Get[tokenResult](t.Context(), db, `SELECT image_url FROM tokens WHERE external_address = $1 AND type = 'profile'`, profileExternalAddr)
		require.NoError(t, err)
		require.NotNil(t, token.ImageURL)
		require.Equal(t, "new_avatar.jpg", *token.ImageURL)
	})
}
