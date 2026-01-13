// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsProfileType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tokenType string
		expected  bool
	}{
		{"Profile type", "profile", true},
		{"Post type", "post", false},
		{"Video type", "video", false},
		{"Article type", "article", false},
		{"Empty type", "", false},
		{"Invalid type", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsProfileType(tt.tokenType)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestIsContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tokenType string
		expected  bool
	}{
		{"Profile type", "profile", false},
		{"Post type", "post", true},
		{"Video type", "video", true},
		{"Article type", "article", true},
		{"Empty type", "", false},
		{"Invalid type", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsContentType(tt.tokenType)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractIonConnectFromTokenExternalAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		externalAddress string
		platform        string
		expected        string
	}{
		{
			name:            "X.com token with full format (31751:pubkey:xxx)",
			externalAddress: "31751:9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f:abc123",
			platform:        PlatformGroupXCom,
			expected:        "9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f",
		},
		{
			name:            "X.com token with 2 parts only",
			externalAddress: "31751:short_pubkey",
			platform:        PlatformGroupXCom,
			expected:        "short_pubkey",
		},
		{
			name:            "X.com token with multiple colons",
			externalAddress: "31751:pubkey123:extra:more:parts",
			platform:        PlatformGroupXCom,
			expected:        "pubkey123",
		},
		{
			name:            "X.com token with only 1 part (invalid format)",
			externalAddress: "just_one_part",
			platform:        PlatformGroupXCom,
			expected:        "",
		},
		{
			name:            "IonConnect platform should return empty",
			externalAddress: "31751:pubkey:extra",
			platform:        PlatformGroupIonConnect,
			expected:        "",
		},
		{
			name:            "Empty external address",
			externalAddress: "",
			platform:        PlatformGroupXCom,
			expected:        "",
		},
		{
			name:            "X.com token with empty pubkey part",
			externalAddress: "31751::extra",
			platform:        PlatformGroupXCom,
			expected:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIonConnectFromTokenExternalAddress(tt.externalAddress, tt.platform)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildAddressesFromExternalAddressAndPlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		externalAddress   string
		platform          string
		bnbBscAddress     string
		ionConnectAddress []string
		expectNil         bool
		expectError       bool
		expectedAddresses *Addresses
	}{
		{
			name:            "All addresses empty - should return nil",
			externalAddress: "",
			platform:        "",
			bnbBscAddress:   "",
			expectNil:       true,
			expectError:     false,
		},
		{
			name:              "All addresses empty with empty ionConnect - should return nil",
			externalAddress:   "",
			platform:          "",
			bnbBscAddress:     "",
			ionConnectAddress: []string{""},
			expectNil:         true,
			expectError:       false,
		},
		{
			name:            "Valid IonConnect address",
			externalAddress: "a:pubkey:creator123",
			platform:        PlatformGroupIonConnect,
			bnbBscAddress:   "",
			expectNil:       false,
			expectError:     false,
			expectedAddresses: &Addresses{
				IonConnect: "a:pubkey:creator123",
			},
		},
		{
			name:            "Valid X.com address",
			externalAddress: "z:twitter:user456",
			platform:        PlatformGroupXCom,
			bnbBscAddress:   "0x123abc",
			expectNil:       false,
			expectError:     false,
			expectedAddresses: &Addresses{
				Twitter:    "z:twitter:user456",
				Blockchain: "0x123abc",
			},
		},
		{
			name:              "Valid X.com address with ionConnect",
			externalAddress:   "y:twitter:post789",
			platform:          PlatformGroupXCom,
			bnbBscAddress:     "0x456def",
			ionConnectAddress: []string{"a:ionpubkey:ionuser"},
			expectNil:         false,
			expectError:       false,
			expectedAddresses: &Addresses{
				Twitter:    "y:twitter:post789",
				Blockchain: "0x456def",
				IonConnect: "a:ionpubkey:ionuser",
			},
		},
		{
			name:              "External address present but platform empty - should return empty addresses",
			externalAddress:   "a:pubkey:creator123",
			platform:          "",
			bnbBscAddress:     "",
			expectNil:         false,
			expectError:       false,
			expectedAddresses: &Addresses{},
		},
		{
			name:            "BnbBsc address present but platform empty - should use blockchain only",
			externalAddress: "",
			platform:        "",
			bnbBscAddress:   "0x789ghi",
			expectNil:       false,
			expectError:     false,
			expectedAddresses: &Addresses{
				Blockchain: "0x789ghi",
			},
		},
		{
			name:              "IonConnect address present but platform empty - should use ionConnect",
			externalAddress:   "",
			platform:          "",
			bnbBscAddress:     "",
			ionConnectAddress: []string{"a:ionpubkey:ionuser"},
			expectNil:         false,
			expectError:       false,
			expectedAddresses: &Addresses{
				IonConnect: "a:ionpubkey:ionuser",
			},
		},
		{
			name:            "Unknown platform - should error",
			externalAddress: "some:address",
			platform:        "unknown_platform",
			bnbBscAddress:   "",
			expectNil:       false,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildAddressesFromExternalAddressAndPlatform(
				tt.externalAddress,
				tt.platform,
				tt.bnbBscAddress,
				tt.ionConnectAddress...,
			)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.expectNil {
				require.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			require.Equal(t, tt.expectedAddresses.IonConnect, result.IonConnect)
			require.Equal(t, tt.expectedAddresses.Twitter, result.Twitter)
			require.Equal(t, tt.expectedAddresses.Blockchain, result.Blockchain)
		})
	}
}
