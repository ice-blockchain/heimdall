// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/subzero/model"
)

func TestGetNFTContentType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		profileContent *model.ProfileMetadataContent
		contentEvent   *model.Event
		expected       NFTContentType
	}{
		{
			name: "should return account type for nil content event with empty collections",
			profileContent: &model.ProfileMetadataContent{
				IONContentNFTCollections: make(map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata),
			},
			contentEvent: nil,
			expected:     NFTContentTypeAccount,
		},
		{
			name: "should return post for text note without video",
			profileContent: &model.ProfileMetadataContent{
				IONContentNFTCollections: map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata{
					"test": {Address: "test", CreatedBy: "test"},
				},
			},
			contentEvent: &model.Event{
				Event: nostr.Event{
					Kind: nostr.KindTextNote,
					Tags: nostr.Tags{},
				},
			},
			expected: NFTContentTypePost,
		},
		{
			name: "should return video for text note with video imeta",
			profileContent: &model.ProfileMetadataContent{
				IONContentNFTCollections: map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata{
					"test": {Address: "test", CreatedBy: "test"},
				},
			},
			contentEvent: &model.Event{
				Event: nostr.Event{
					Kind: nostr.KindTextNote,
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/video.mp4", "m video/mp4"},
					},
				},
			},
			expected: NFTContentTypeVideo,
		},
		{
			name: "should return video for editable text note with video imeta",
			profileContent: &model.ProfileMetadataContent{
				IONContentNFTCollections: map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata{
					"test": {Address: "test", CreatedBy: "test"},
				},
			},
			contentEvent: &model.Event{
				Event: nostr.Event{
					Kind: model.CustomIONKindEditableTextNote,
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/video.webm", "m video/webm"},
					},
				},
			},
			expected: NFTContentTypeVideo,
		},
		{
			name: "should return article for article event",
			profileContent: &model.ProfileMetadataContent{
				IONContentNFTCollections: map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata{
					"test": {Address: "test", CreatedBy: "test"},
				},
			},
			contentEvent: &model.Event{
				Event: nostr.Event{
					Kind: nostr.KindArticle,
					Tags: nostr.Tags{},
				},
			},
			expected: NFTContentTypeArticle,
		},
		{
			name: "should return post for unknown event kind",
			profileContent: &model.ProfileMetadataContent{
				IONContentNFTCollections: map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata{
					"test": {Address: "test", CreatedBy: "test"},
				},
			},
			contentEvent: &model.Event{
				Event: nostr.Event{
					Kind: 9999, // Unknown kind
					Tags: nostr.Tags{},
				},
			},
			expected: NFTContentTypePost,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := getNFTContentType(tc.profileContent, tc.contentEvent)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestIsAccountType(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		profileContent model.ProfileMetadataContent
		contentEvent   *model.Event
		expectedResult bool
		expectedError  error
	}{
		{
			name: "should return true for nil content event with empty collections",
			profileContent: model.ProfileMetadataContent{
				IONContentNFTCollections: make(map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata),
			},
			contentEvent:   nil,
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "should return true for nil content event with nil collections",
			profileContent: model.ProfileMetadataContent{
				IONContentNFTCollections: nil,
			},
			contentEvent:   nil,
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "should return false for non-nil content event",
			profileContent: model.ProfileMetadataContent{
				IONContentNFTCollections: make(map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata),
			},
			contentEvent: &model.Event{
				Event: nostr.Event{Kind: nostr.KindTextNote},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "should return false for nil content event with existing collections",
			profileContent: model.ProfileMetadataContent{
				IONContentNFTCollections: map[model.IONContentNFTCollectionName]model.IONContentNFTCollectionMetadata{
					"test": {Address: "test", CreatedBy: "test"},
				},
			},
			contentEvent:   nil,
			expectedResult: false,
			expectedError:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := isAccountType(tc.profileContent, tc.contentEvent)
			require.Equal(t, tc.expectedError, err)
			require.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestHasVideoImeta(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		event    *model.Event
		expected bool
	}{
		{
			name: "should return true for video/mp4",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/video.mp4", "m video/mp4"},
					},
				},
			},
			expected: true,
		},
		{
			name: "should return true for video/webm",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/video.webm", "m video/webm"},
					},
				},
			},
			expected: true,
		},
		{
			name: "should return true for generic video type",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/video", "m video"},
					},
				},
			},
			expected: true,
		},
		{
			name: "should return false for image/jpeg",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/image.jpg", "m image/jpeg"},
					},
				},
			},
			expected: false,
		},
		{
			name: "should return false for no imeta tags",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{},
				},
			},
			expected: false,
		},
		{
			name: "should return false for malformed imeta tag",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "invalid-format"},
					},
				},
			},
			expected: false,
		},
		{
			name: "should return false for imeta without mime type",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/file", "size 1024"},
					},
				},
			},
			expected: false,
		},
		{
			name: "should return true for multiple imeta tags with video",
			event: &model.Event{
				Event: nostr.Event{
					Tags: nostr.Tags{
						{"imeta", "url https://example.com/image.jpg", "m image/jpeg"},
						{"imeta", "url https://example.com/video.mp4", "m video/mp4"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := hasVideoImeta(tc.event)
			require.Equal(t, tc.expected, result)
		})
	}
}
