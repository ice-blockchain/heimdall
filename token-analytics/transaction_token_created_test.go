// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTokenType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                      string
		externalType              byte
		externalAddress           string
		expectedTokenType         string
		expectedMasterPubkeyOrXID string
		expectError               bool
	}{
		// IonConnect profile tokens (type 'a')
		{
			name:                      "valid IonConnect profile",
			externalType:              'a',
			externalAddress:           "pubkey123",
			expectedTokenType:         TokenTypeProfile,
			expectedMasterPubkeyOrXID: "pubkey123",
			expectError:               false,
		},
		// IonConnect post tokens (type 'b')
		{
			name:                      "valid IonConnect post",
			externalType:              'b',
			externalAddress:           "30023:pubkey456:post1",
			expectedTokenType:         TokenTypePost,
			expectedMasterPubkeyOrXID: "pubkey456",
			expectError:               false,
		},
		{
			name:            "invalid IonConnect post - missing masterpubkey",
			externalType:    'b',
			externalAddress: "30023::post1",
			expectError:     true,
		},
		{
			name:            "invalid IonConnect post - not enough parts",
			externalType:    'b',
			externalAddress: "30023",
			expectError:     true,
		},
		// IonConnect video tokens (type 'c')
		{
			name:                      "valid IonConnect video",
			externalType:              'c',
			externalAddress:           "30024:pubkey789:video1",
			expectedTokenType:         TokenTypeVideo,
			expectedMasterPubkeyOrXID: "pubkey789",
			expectError:               false,
		},
		{
			name:            "invalid IonConnect video - missing masterpubkey",
			externalType:    'c',
			externalAddress: "30024::video1",
			expectError:     true,
		},
		// IonConnect article tokens (type 'd')
		{
			name:                      "valid IonConnect article",
			externalType:              'd',
			externalAddress:           "30023:pubkeyabc:article1",
			expectedTokenType:         TokenTypeArticle,
			expectedMasterPubkeyOrXID: "pubkeyabc",
			expectError:               false,
		},
		{
			name:            "invalid IonConnect article - missing masterpubkey",
			externalType:    'd',
			externalAddress: "30023::article1",
			expectError:     true,
		},
		// IonConnect comment tokens (type 'e')
		{
			name:                      "valid IonConnect comment with event ID",
			externalType:              'e',
			externalAddress:           "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			expectedTokenType:         TokenTypeComment,
			expectedMasterPubkeyOrXID: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			expectError:               false,
		},
		{
			name:                      "valid IonConnect comment with colon-delimited address",
			externalType:              'e',
			externalAddress:           "30175:pubkey123:eventid456",
			expectedTokenType:         TokenTypeComment,
			expectedMasterPubkeyOrXID: "30175:pubkey123:eventid456",
			expectError:               false,
		},
		// X.com profile tokens (type 'z')
		{
			name:                      "valid X.com profile",
			externalType:              'z',
			externalAddress:           "handle123",
			expectedTokenType:         TokenTypeProfile,
			expectedMasterPubkeyOrXID: "handle123",
			expectError:               false,
		},
		// X.com post tokens (type 'y')
		{
			name:                      "valid X.com post",
			externalType:              'y',
			externalAddress:           "1234567890",
			expectedTokenType:         TokenTypePost,
			expectedMasterPubkeyOrXID: "1234567890",
			expectError:               false,
		},
		// X.com video tokens (type 'x')
		{
			name:                      "valid X.com video",
			externalType:              'x',
			externalAddress:           "9876543210",
			expectedTokenType:         TokenTypeVideo,
			expectedMasterPubkeyOrXID: "9876543210",
			expectError:               false,
		},
		// X.com article tokens (type 'w')
		{
			name:                      "valid X.com article",
			externalType:              'w',
			externalAddress:           "1122334455",
			expectedTokenType:         TokenTypeArticle,
			expectedMasterPubkeyOrXID: "1122334455",
			expectError:               false,
		},
		// X.com comment tokens (type 'v')
		{
			name:                      "valid X.com comment",
			externalType:              'v',
			externalAddress:           "5566778899",
			expectedTokenType:         TokenTypeComment,
			expectedMasterPubkeyOrXID: "5566778899",
			expectError:               false,
		},
		// Edge cases
		{
			name:            "empty external address",
			externalType:    'a',
			externalAddress: "",
			expectError:     true,
		},
		{
			name:            "unknown external type",
			externalType:    'k',
			externalAddress: "12345",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokenType, _, masterPubkeyOrXID, err := parseTokenType(tt.externalType, tt.externalAddress)

			if tt.expectError {
				require.Error(t, err, "Expected error for externalType=%c, externalAddress=%s", tt.externalType, tt.externalAddress)
				require.Empty(t, tokenType, "Token type should be empty on error")
				require.Empty(t, masterPubkeyOrXID, "Master pubkey/X ID should be empty on error")
			} else {
				require.NoError(t, err, "Unexpected error for externalType=%c, externalAddress=%s", tt.externalType, tt.externalAddress)
				require.Equal(t, tt.expectedTokenType, tokenType, "Token type mismatch")
				require.Equal(t, tt.expectedMasterPubkeyOrXID, masterPubkeyOrXID, "Master pubkey/X ID mismatch")
			}
		})
	}
}
