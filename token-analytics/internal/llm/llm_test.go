// SPDX-License-Identifier: ice License 1.0

package llm

import (
	_ "embed"
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed .testdata/test_validate_big.webp.bin
	testImageWebpBig []byte
	//go:embed .testdata/test_validate_ok.webp.bin
	testImageWebpOK []byte
)

func TestValidateWebpImage(t *testing.T) {
	t.Parallel()

	t.Run("Invalid base64", func(t *testing.T) {
		err := ValidateWebpImage("invalid-base64")
		require.Error(t, err)
	})
	t.Run("Invalid webp data", func(t *testing.T) {
		err := ValidateWebpImage(base64.StdEncoding.EncodeToString([]byte("not a webp image")))
		require.Error(t, err)
	})
	t.Run("Large dimensions", func(t *testing.T) {
		b64image := base64.StdEncoding.EncodeToString(testImageWebpBig)
		err := ValidateWebpImage(b64image)
		require.Error(t, err)
	})
	t.Run("Valid webp image", func(t *testing.T) {
		b64image := base64.StdEncoding.EncodeToString(testImageWebpOK)
		err := ValidateWebpImage(b64image)
		require.NoError(t, err)
	})
}

func TestCapitalizeFirst(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single lowercase ASCII letter",
			input:    "hello",
			expected: "Hello",
		},
		{
			name:     "single uppercase ASCII letter",
			input:    "Hello",
			expected: "Hello",
		},
		{
			name:     "already capitalized",
			input:    "HELLO",
			expected: "HELLO",
		},
		{
			name:     "Spanish lowercase á",
			input:    "árbol",
			expected: "Árbol",
		},
		{
			name:     "Spanish lowercase é",
			input:    "época",
			expected: "Época",
		},
		{
			name:     "Spanish lowercase ñ",
			input:    "niño",
			expected: "Niño",
		},
		{
			name:     "Spanish lowercase ü",
			input:    "übung",
			expected: "Übung",
		},
		{
			name:     "Polish lowercase ł",
			input:    "łódka",
			expected: "Łódka",
		},
		{
			name:     "Polish lowercase ą",
			input:    "ąd",
			expected: "Ąd",
		},
		{
			name:     "Polish lowercase ć",
			input:    "ćma",
			expected: "Ćma",
		},
		{
			name:     "Polish lowercase ź",
			input:    "źródło",
			expected: "Źródło",
		},
		{
			name:     "Polish lowercase ż",
			input:    "żaba",
			expected: "Żaba",
		},
		{
			name:     "already capitalized Spanish",
			input:    "Árbol",
			expected: "Árbol",
		},
		{
			name:     "already capitalized Polish",
			input:    "Łódka",
			expected: "Łódka",
		},
		{
			name:     "mixed ASCII and accented characters",
			input:    "élève",
			expected: "Élève",
		},
		{
			name:     "single emoji (multi-byte)",
			input:    "🎉party",
			expected: "🎉party",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capitalizeFirst(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSelectFrames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		webpFrames  []string
		maxFrames   int
		expectedIdx []int // indices of expected selected frames.
	}{
		{
			name:        "32 frames, max 16",
			webpFrames:  makeFrames(32),
			maxFrames:   16,
			expectedIdx: []int{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
		},
		{
			name:        "10 frames, max 5",
			webpFrames:  makeFrames(10),
			maxFrames:   5,
			expectedIdx: []int{0, 2, 4, 6, 8},
		},
		{
			name:        "10 frames, max 10",
			webpFrames:  makeFrames(10),
			maxFrames:   10,
			expectedIdx: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			name:        "9 frames, max 3",
			webpFrames:  makeFrames(9),
			maxFrames:   3,
			expectedIdx: []int{0, 3, 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectFrames(tt.webpFrames, tt.maxFrames)
			require.Equal(t, len(tt.expectedIdx), len(result))

			for i, expectedIdx := range tt.expectedIdx {
				require.Equal(t, tt.webpFrames[expectedIdx], result[i])
			}
		})
	}
}

func makeFrames(n int) []string {
	frames := make([]string, n)
	for i := range n {
		frames[i] = "frame_" + strconv.Itoa(i)
	}
	return frames
}
