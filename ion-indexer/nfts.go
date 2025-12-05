// SPDX-License-Identifier: ice License 1.0

package ion_indexer

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
)

func (i *indexer) ListNFTs(ctx context.Context, walletAddr string, paginationToken string, limit uint64) ([]WalletNFT, *string, error) {
	if paginationToken == "" {
		paginationToken = "0" // Basically offset, but on 3rd party wallet provider they use strings, we try to mimic to their endpoint
	}
	offset, err := strconv.ParseUint(paginationToken, 10, 64)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse pagination token: %v", paginationToken)
	}
	nfts, newPagination, err := i.listNFTs(ctx, walletAddr, offset, limit)
	return nfts, newPagination, errors.Wrapf(err, "failed to fetch NFTs for wallet %v from ion indexer", walletAddr)
}

func (i *indexer) listNFTs(ctx context.Context, walletAddress string, offset, limit uint64) ([]WalletNFT, *string, error) {
	params := map[string]string{
		"offset":        fmt.Sprintf("%v", offset),
		"owner_address": walletAddress,
	}
	if limit < defaultIndexerReqLimit {
		params["limit"] = fmt.Sprintf("%v", limit)
	}
	total := uint64(0)
	nfts, newOffset, err := indexerReq[WalletNFT](ctx, i, "/indexer/v3/nft/items", params, func(data []byte) ([]WalletNFT, bool, error) {
		var nftItems getNftItemsIndexerResponse
		if err := json.UnmarshalContext(ctx, data, &nftItems); err != nil {
			return nil, false, err
		}
		res := []WalletNFT{}
		for _, nft := range nftItems.NftItems {
			var collectionMetadata map[string]string
			indexedCollectionMeta, hasCollectionMeta := nftItems.Metadata[nft.CollectionAddress]
			if hasCollectionMeta && indexedCollectionMeta.IsIndexed && len(indexedCollectionMeta.TokenInfo) > 0 {
				collectionMetadata = map[string]string{
					"name":        indexedCollectionMeta.TokenInfo[0].Name,
					"description": indexedCollectionMeta.TokenInfo[0].Description,
					"image":       indexedCollectionMeta.TokenInfo[0].Image,
					"symbol":      indexedCollectionMeta.TokenInfo[0].Symbol,
				}
			}
			symbol := ""
			if collectionMetadata["symbol"] != "" {
				symbol = collectionMetadata["symbol"]
			}
			if symbol == "" { // fallback for older collections
				if itemMeta, hasItemMeta := nftItems.Metadata[nft.Address]; hasItemMeta && len(itemMeta.TokenInfo) > 0 {
					symbol = itemMeta.TokenInfo[0].Extra.AuthorId
					if symbol == "" {
						symbol = itemMeta.TokenInfo[0].Extra.AccountId
					}
				}
			}
			res = append(res, WalletNFT(map[string]any{
				"kind":     "TEP-62",
				"contract": nft.CollectionAddress,
				"tokenId":  nft.Index,
				"tokenUri": nft.Content.Uri,
				"symbol":   symbol,
				// Using that data to populate collection info in coins / collection db cache to avoid cg calls
				// as it will not find anything for our custom collections anyway
				NFTCollectionMetadataIndexedKey: collectionMetadata,
			}))
		}
		continuePagination := true
		total += uint64(len(res))
		if uint64(len(res)) < defaultIndexerReqLimit || total >= limit {
			continuePagination = false
		}
		return res, continuePagination, nil
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to fetch nfts from ion indexer for wallet %v", walletAddress)
	}
	if uint64(len(nfts)) >= limit {
		paginationToken := fmt.Sprintf("%v", newOffset)
		return nfts, &paginationToken, nil
	}
	return nfts, nil, nil
}
