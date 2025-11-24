// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func TestParseTokenType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		ionConnectAddress    string
		expectedTokenType    string
		expectedMasterPubkey string
		expectError          bool
	}{
		{
			name:                 "valid profile token (kind 0)",
			ionConnectAddress:    "0:npub1abc123:profile",
			expectedTokenType:    TokenTypeProfile,
			expectedMasterPubkey: "npub1abc123",
			expectError:          false,
		},
		{
			name:                 "valid post token (kind 1)",
			ionConnectAddress:    "1:npub1def456:post123",
			expectedTokenType:    TokenTypePost,
			expectedMasterPubkey: "npub1def456",
			expectError:          false,
		},
		{
			name:                 "valid article token (kind 30023)",
			ionConnectAddress:    "30023:npub1xyz789:article456",
			expectedTokenType:    TokenTypeArticle,
			expectedMasterPubkey: "npub1xyz789",
			expectError:          false,
		},
		{
			name:                 "valid editable text note (kind 30175)",
			ionConnectAddress:    "30175:npub1test123:note789",
			expectedTokenType:    TokenTypePost,
			expectedMasterPubkey: "npub1test123",
			expectError:          false,
		},
		{
			name:              "invalid format - missing parts",
			ionConnectAddress: "0",
			expectError:       true,
		},
		{
			name:              "invalid format - empty masterpubkey",
			ionConnectAddress: "0::profile",
			expectError:       true,
		},
		{
			name:              "invalid format - empty kind",
			ionConnectAddress: ":npub1abc123:profile",
			expectError:       true,
		},
		{
			name:              "invalid kind - not a number",
			ionConnectAddress: "abc:npub1abc123:profile",
			expectError:       true,
		},
		{
			name:              "unknown kind",
			ionConnectAddress: "99999:npub1abc123:unknown",
			expectError:       true,
		},
		{
			name:              "empty string",
			ionConnectAddress: "",
			expectError:       true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokenType, masterPubkey, err := parseTokenType(tt.ionConnectAddress)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, tokenType)
				assert.Empty(t, masterPubkey)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedTokenType, tokenType)
				assert.Equal(t, tt.expectedMasterPubkey, masterPubkey)
			}
		})
	}
}

func TestSaveTokenMetadata(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ta := &tokenAnalytics{
		ingestedDataDB: testDB,
	}

	t.Run("successfully saves token metadata with valid ionConnectAddress", func(t *testing.T) {
		t.Parallel()
		masterPubkey := "npub1test123"
		username := "testuser"
		helperInsertTestUser(t, ctx, testDB, masterPubkey, username, "", "", false)

		contractAddress := common.HexToAddress("0xabc1234567890123456789012345678901234567")
		ionConnectAddress := "30023:" + masterPubkey + ":article123"

		event := &bondingcurve.LogTokenCreated{
			Address:           contractAddress,
			Name:              "Test Token",
			Symbol:            "TEST",
			IonConnectAddress: ionConnectAddress,
			TotalSupply:       big.NewInt(1000000000000000000), // 1 token
		}

		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_create_123",
			BlockNumber:     12345,
			FromAddress:     "0x1111111111111111111111111111111111111111",
			BlockTimestamp:  now,
		}

		err := ta.saveTokenMetadata(ctx, tx, event)
		require.NoError(t, err)

		type tokenResult struct {
			ContractAddress     string `db:"contract_address"`
			IonConnectAddress   string `db:"ion_connect_address"`
			Ticker              string `db:"ticker"`
			TotalSupply         string `db:"total_supply"`
			CreatorMasterPubkey string `db:"creator_master_pubkey"`
			Type                string `db:"type"`
		}

		tokens, err := storage.Select[tokenResult](ctx, testDB,
			"SELECT contract_address, ion_connect_address, ticker, total_supply, creator_master_pubkey, type FROM tokens WHERE ion_connect_address = $1",
			ionConnectAddress)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		assert.Equal(t, "0xabc1234567890123456789012345678901234567", token.ContractAddress)
		assert.Equal(t, ionConnectAddress, token.IonConnectAddress)
		assert.Equal(t, username, token.Ticker) // ticker = username
		assert.Equal(t, "1000000000000000000", token.TotalSupply)
		assert.Equal(t, masterPubkey, token.CreatorMasterPubkey)
		assert.Equal(t, TokenTypeArticle, token.Type)
	})

	t.Run("successfully updates token on conflict", func(t *testing.T) {
		t.Parallel()
		masterPubkey := "npub1update123"
		username := "updateuser"
		helperInsertTestUser(t, ctx, testDB, masterPubkey, username, "", "", false)

		ionConnectAddress := "1:" + masterPubkey + ":post456"
		contractAddress := common.HexToAddress("0xdef1234567890123456789012345678901234567")

		event1 := &bondingcurve.LogTokenCreated{
			Address:           contractAddress,
			Name:              "Test Post Token",
			Symbol:            "POST",
			IonConnectAddress: ionConnectAddress,
			TotalSupply:       big.NewInt(500000000000000000),
		}

		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_update_1",
			BlockNumber:     12346,
			FromAddress:     "0x2222222222222222222222222222222222222222",
			BlockTimestamp:  now,
		}

		err := ta.saveTokenMetadata(ctx, tx, event1)
		require.NoError(t, err)

		event2 := &bondingcurve.LogTokenCreated{
			Address:           contractAddress,
			Name:              "Updated Post Token",
			Symbol:            "POST2",
			IonConnectAddress: ionConnectAddress,
			TotalSupply:       big.NewInt(600000000000000000),
		}

		tx2 := &txEvent{
			TransactionHash: "0xtest_update_2",
			BlockNumber:     12347,
			FromAddress:     "0x2222222222222222222222222222222222222222",
			BlockTimestamp:  now,
		}

		err = ta.saveTokenMetadata(ctx, tx2, event2)
		require.NoError(t, err)

		type tokenResult struct {
			TotalSupply string `db:"total_supply"`
		}

		tokens, err := storage.Select[tokenResult](ctx, testDB,
			"SELECT total_supply FROM tokens WHERE ion_connect_address = $1",
			ionConnectAddress)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, "600000000000000000", tokens[0].TotalSupply)
	})

	t.Run("fails with empty ionConnectAddress", func(t *testing.T) {
		t.Parallel()
		contractAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")
		event := &bondingcurve.LogTokenCreated{
			Address:           contractAddress,
			Name:              "Test Token",
			Symbol:            "TEST",
			IonConnectAddress: "", // Empty!
			TotalSupply:       big.NewInt(1000000000000000000),
		}

		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_empty",
			BlockNumber:     12348,
			FromAddress:     "0x3333333333333333333333333333333333333333",
			BlockTimestamp:  now,
		}

		err := ta.saveTokenMetadata(ctx, tx, event)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ion_connect_address is empty")
	})

	t.Run("fails with invalid ionConnectAddress format", func(t *testing.T) {
		t.Parallel()
		contractAddress := common.HexToAddress("0x4444444444444444444444444444444444444444")
		event := &bondingcurve.LogTokenCreated{
			Address:           contractAddress,
			Name:              "Test Token",
			Symbol:            "TEST",
			IonConnectAddress: "invalid",
			TotalSupply:       big.NewInt(1000000000000000000),
		}

		now := time.Now()
		tx := &txEvent{
			TransactionHash: "0xtest_invalid",
			BlockNumber:     12349,
			FromAddress:     "0x5555555555555555555555555555555555555555",
			BlockTimestamp:  now,
		}

		err := ta.saveTokenMetadata(ctx, tx, event)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse ion_connect_address")
	})
}
