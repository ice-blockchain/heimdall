// SPDX-License-Identifier: ice License 1.0

package hashtagstatistics

import (
	"reflect"
	"sort"
	"testing"
)

func TestExtractUniqueHashtags(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "empty string",
			content:  "",
			expected: nil,
		},
		{
			name:     "no hashtags",
			content:  "This is a simple text without any hashtags",
			expected: nil,
		},
		{
			name:     "single hashtag",
			content:  "This is a text with #hashtag",
			expected: []string{"hashtag"},
		},
		{
			name:     "multiple hashtags",
			content:  "This text has #multiple #hashtags in it",
			expected: []string{"multiple", "hashtags"},
		},
		{
			name:     "duplicate hashtags",
			content:  "#duplicate and again #duplicate #hashtag",
			expected: []string{"duplicate", "hashtag"},
		},
		{
			name:     "mixed case hashtags",
			content:  "#UPPERCASE #lowercase #MixedCase",
			expected: []string{"uppercase", "lowercase", "mixedcase"},
		},
		{
			name:     "hashtags with numbers and underscores",
			content:  "#hash1 #hash_2 #hash3_tag",
			expected: []string{"hash1", "hash_2", "hash3_tag"},
		},
		{
			name:     "hashtags with special characters",
			content:  "#hash! #hash@ is not valid, but #valid_1 is",
			expected: []string{"hash", "valid_1"},
		},
		{
			name:     "hashtags at different positions",
			content:  "#start middle #middle end#notvalid #end",
			expected: []string{"start", "middle", "notvalid", "end"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := extractUniqueHashtags(tt.content)
			sort.Strings(actual)
			sort.Strings(tt.expected)

			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("extractUniqueHashtags() = %v, want %v", actual, tt.expected)
			}
		})
	}
}
