// SPDX-License-Identifier: ice License 1.0

package llm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecuteNameTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		creator   string
		content   string
		hasImages bool
		hasVideo  bool
	}{
		{"Alice", "This is a test content.", false, false},
		{"Bob", "Images only.", true, false},
		{"Charlie", "Video content here.", false, true},
		{"Diana", "Mixed media content.", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.content, func(t *testing.T) {
			result, err := executeNameTemplate(tt.creator, tt.content, tt.hasImages, tt.hasVideo)
			require.NoError(t, err)
			require.NotEmpty(t, result)
			require.Contains(t, result, tt.creator)
			if tt.hasImages || tt.hasVideo {
				require.Contains(t, result, tt.content)
			}
		})
	}
}

func TestExecuteImageTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		creator   string
		content   string
		ticker    string
		name      string
		hasImages bool
		hasVideo  bool
	}{
		{"Alice", "This is a test content.", "TST", "TestToken", false, false},
		{"Bob", "Another content example with pics.", "ANR", "AnotherToken", true, false},
		{"Charlie", "Video content here.", "VID", "VideoToken", false, true},
		{"Diana", "Mixed media content.", "MIX", "MixedToken", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.content, func(t *testing.T) {
			result, err := executeImageTemplate(tt.creator, tt.content, tt.name, tt.ticker, tt.hasImages, tt.hasVideo)
			require.NoError(t, err)
			require.NotEmpty(t, result)
			require.Contains(t, result, tt.ticker)
			require.Contains(t, result, tt.name)
			if tt.hasImages || tt.hasVideo {
				require.Contains(t, result, tt.content)
			}
		})
	}
}
