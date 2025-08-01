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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := getNFTContentType(tc.contentEvent)
			require.Equal(t, tc.expected, result)
		})
	}
}
