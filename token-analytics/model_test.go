// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPlatformFromExternalAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		address  string
		expected Platform
	}{
		{"IonConnect Profile", "a123456", PlatformIonConnectProfile},
		{"IonConnect Post", "b123456:tag", PlatformIonConnectPost},
		{"IonConnect Video", "c30175:pubkey:tag", PlatformIonConnectVideo},
		{"IonConnect Article", "d30023:pubkey:uuid", PlatformIonConnectArticle},
		{"X.com Article", "w123456", PlatformXComArticle},
		{"X.com Video", "x123456", PlatformXComVideo},
		{"X.com Post", "y123456", PlatformXComPost},
		{"X.com Profile", "z123456", PlatformXComProfile},
		{"Empty address", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPlatformFromExternalAddress(tt.address)
			require.Equal(t, tt.expected, result)
		})
	}
}

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
