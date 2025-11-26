// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func TestOnPairRegistered(t *testing.T) {
	baseTokenAddr := "0x2c73996babf1a06c2c057177353293f7ca0907c8"                  // ION token (from real event)
	tokenAddr := "0x7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8"                      // Community token (from real event)
	pairId := "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15" // From real event
	ionConnectAddr := "30023:creator_pubkey:test_token"

	t.Run("updates_base_token_for_existing_token", func(t *testing.T) {
		t.Parallel()
		testCtx := t.Context()

		masterPubkey := "creator_pubkey"
		helperInsertTestUser(t, testCtx, testDB, masterPubkey, "creator", "Creator User", "", false)
		helperInsertTestToken(t, testCtx, testDB, tokenAddr, ionConnectAddr, "TEST", "30023", masterPubkey,
			"1000000000000000000000000", 0.0, 0.0, 0)

		type tokenResult struct {
			BaseToken *string `db:"base_token"`
		}
		tokens, err := storage.Select[tokenResult](testCtx, testDB,
			"SELECT base_token FROM tokens WHERE contract_address = $1", tokenAddr)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Nil(t, tokens[0].BaseToken, "base_token should be NULL initially")

		event := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash(pairId),
			BaseToken:  common.HexToAddress(baseTokenAddr),
			OtherToken: common.HexToAddress(tokenAddr),
		}

		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_pair_registered_123",
			BlockNumber:     74287042,
			FromAddress:     "0xcreatoraddress",
			BlockTimestamp:  now,
		}

		ta := New(t.Context()).(*tokenAnalytics)

		err = ta.onPairRegistered(testCtx, tx, event)
		require.NoError(t, err, "onPairRegistered should succeed")

		tokens, err = storage.Select[tokenResult](testCtx, testDB,
			"SELECT base_token FROM tokens WHERE contract_address = $1", tokenAddr)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.NotNil(t, tokens[0].BaseToken, "base_token should be set after PairRegistered")
		assert.Equal(t, baseTokenAddr, *tokens[0].BaseToken)

		t.Logf("Successfully updated base_token from NULL to %s", *tokens[0].BaseToken)
	})

	t.Run("fails_when_token_does_not_exist", func(t *testing.T) {
		t.Parallel()
		testCtx := t.Context()

		nonExistentTokenAddr := "0x9999999999999999999999999999999999999999"

		event := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash(pairId),
			BaseToken:  common.HexToAddress(baseTokenAddr),
			OtherToken: common.HexToAddress(nonExistentTokenAddr),
		}

		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_pair_nonexistent_456",
			BlockNumber:     74287042,
			FromAddress:     "0xcreatoraddress",
			BlockTimestamp:  now,
		}

		ta := New(t.Context()).(*tokenAnalytics)

		err := ta.onPairRegistered(testCtx, tx, event)
		require.NoError(t, err, "onPairRegistered should not fail even if token doesn't exist")

		t.Log("onPairRegistered succeeded (UPDATE with 0 affected rows doesn't error in Postgres)")
	})

	t.Run("updates_base_token_multiple_times", func(t *testing.T) {
		t.Parallel()
		testCtx := t.Context()

		masterPubkey := "multi_creator_pubkey"
		helperInsertTestUser(t, testCtx, testDB, masterPubkey, "multicreator", "Multi Creator", "", false)

		tokenAddr2 := "0x8888888888888888888888888888888888888888"
		ionConnectAddr2 := "30023:multi_creator_pubkey:multi_token"

		helperInsertTestToken(t, testCtx, testDB, tokenAddr2, ionConnectAddr2, "MULTI", "30023", masterPubkey,
			"1000000000000000000000000", 0.0, 0.0, 0)

		ta := New(t.Context()).(*tokenAnalytics)

		baseToken1 := "0x1111111111111111111111111111111111111111"
		event1 := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
			BaseToken:  common.HexToAddress(baseToken1),
			OtherToken: common.HexToAddress(tokenAddr2),
		}
		now := time.Now()
		tx1 := &txEvent{
			TransactionHash: "0xtest_multi_1",
			BlockNumber:     1000,
			FromAddress:     "0xcreatoraddress",
			BlockTimestamp:  now,
		}

		err := ta.onPairRegistered(testCtx, tx1, event1)
		require.NoError(t, err)

		type tokenResult struct {
			BaseToken string `db:"base_token"`
		}
		tokens, err := storage.Select[tokenResult](testCtx, testDB,
			"SELECT base_token FROM tokens WHERE contract_address = $1", tokenAddr2)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, baseToken1, tokens[0].BaseToken)

		baseToken2 := "0x2222222222222222222222222222222222222222"
		event2 := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
			BaseToken:  common.HexToAddress(baseToken2),
			OtherToken: common.HexToAddress(tokenAddr2),
		}
		tx2 := &txEvent{
			TransactionHash: "0xtest_multi_2",
			BlockNumber:     2000,
			FromAddress:     "0xcreatoraddress",
			BlockTimestamp:  now,
		}

		err = ta.onPairRegistered(testCtx, tx2, event2)
		require.NoError(t, err)

		tokens, err = storage.Select[tokenResult](testCtx, testDB,
			"SELECT base_token FROM tokens WHERE contract_address = $1", tokenAddr2)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, baseToken2, tokens[0].BaseToken, "base_token should be updated to second value")

		t.Logf("Successfully updated base_token from %s to %s", baseToken1, baseToken2)
	})

	t.Run("handles_checksum_addresses_correctly", func(t *testing.T) {
		t.Parallel()
		testCtx := t.Context()

		masterPubkey := "checksum_creator"
		helperInsertTestUser(t, testCtx, testDB, masterPubkey, "checksumcreator", "Checksum Creator", "", false)

		checksumTokenAddr := "0xAbCdEf1234567890123456789012345678901234"
		checksumBaseToken := "0x1234567890AbCdEf1234567890AbCdEf12345678"
		ionConnectAddr3 := "30023:checksum_creator:checksum_token"

		helperInsertTestToken(t, testCtx, testDB, strings.ToLower(checksumTokenAddr), ionConnectAddr3, "CSUM", "30023", masterPubkey,
			"1000000000000000000000000", 0.0, 0.0, 0)

		ta := New(t.Context()).(*tokenAnalytics)

		event := &bondingcurve.LogPairRegistered{
			PairId:     common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
			BaseToken:  common.HexToAddress(checksumBaseToken),
			OtherToken: common.HexToAddress(checksumTokenAddr),
		}
		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_checksum_789",
			BlockNumber:     3000,
			FromAddress:     "0xcreatoraddress",
			BlockTimestamp:  now,
		}

		err := ta.onPairRegistered(testCtx, tx, event)
		require.NoError(t, err)

		type tokenResult struct {
			BaseToken string `db:"base_token"`
		}
		tokens, err := storage.Select[tokenResult](testCtx, testDB,
			"SELECT base_token FROM tokens WHERE contract_address = LOWER($1)", checksumTokenAddr)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		expectedLowercase := strings.ToLower(common.HexToAddress(checksumBaseToken).Hex())
		assert.Equal(t, expectedLowercase, tokens[0].BaseToken,
			"base_token should match (case-insensitive)")

		t.Logf("Successfully handled checksum addresses: token=%s, base=%s (stored as %s)",
			checksumTokenAddr, checksumBaseToken, tokens[0].BaseToken)
	})
}
