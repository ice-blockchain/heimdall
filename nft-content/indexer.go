// SPDX-License-Identifier: ice License 1.0

package nftcontent

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	stdlibtime "time"

	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"

	"github.com/ice-blockchain/wintr/log"
)

func init() {
	req.DefaultClient().GetClient().Transport = &http2.Transport{}
	req.DefaultClient().GetClient().Timeout = 30 * stdlibtime.Second
	req.DefaultClient().SetJsonMarshal(json.Marshal)
	req.DefaultClient().SetJsonUnmarshal(json.Unmarshal)
}

func (n *nftContent) listNFTs(ctx context.Context, walletAddress string) ([]WalletNFT, error) {
	nfts, err := indexerReq[WalletNFT](ctx, n, "/indexer/v3/nft/items", map[string]string{
		"owner_address": walletAddress,
	}, func(data []byte) ([]WalletNFT, bool, error) {
		var nftItems getNftItemsIndexerResponse
		if err := json.UnmarshalContext(ctx, data, &nftItems); err != nil {
			return nil, false, err
		}
		res := []WalletNFT{}
		for _, nft := range nftItems.NftItems {
			var collectionMetadata map[string]string
			indexedCollectionMeta, hasCollectionMeta := nftItems.Metadata[nft.CollectionAddress]
			if hasCollectionMeta && len(indexedCollectionMeta.TokenInfo) > 0 {
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
				CollectionMetadataIndexedKey: collectionMetadata,
			}))
		}
		continuePagination := true
		if len(res) < defaultIndexerReqLimit {
			continuePagination = false
		}
		return res, continuePagination, nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch nfts from ion indexer for wallet %v")
	}
	return nfts, nil
}

func indexerReq[T any](ctx context.Context, i *nftContent, relativeUrl string, params map[string]string, unmarshal func([]byte) ([]T, bool, error)) ([]T, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if _, hasLimit := params["limit"]; !hasLimit {
		params["limit"] = fmt.Sprintf("%v", defaultIndexerReqLimit)
	}

	if resp, err := req.C().SetBaseURL(i.config.Indexer.ION).R().
		SetContext(ctx).
		SetRetryCount(3).
		SetRetryInterval(func(resp *req.Response, attempt int) stdlibtime.Duration {
			return 1 * stdlibtime.Second
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to call indexer %v %v, retrying...", i.config.Indexer.ION, relativeUrl))
			} else {
				log.Error(errors.Errorf("failed to call indexer %v with status code:%v, retrying...", i.config.Indexer.ION, relativeUrl, resp.GetStatusCode()))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() != http.StatusOK
		}).
		SetQueryParams(params).
		SetHeader("Accept", "application/json").
		Get(relativeUrl); err != nil {
		return nil, errors.Wrapf(err, "failed to call indexer %v %v", i.config.Indexer.ION, relativeUrl)

	} else if statusCode := resp.GetStatusCode(); statusCode != http.StatusOK {
		return nil, errors.Errorf("failed to check indexer %v %v with status code:%v", i.config.Indexer.ION, relativeUrl, statusCode)
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, errors.Wrapf(err2, "failed to read body of indexer %v %v response", i.config.Indexer.ION, relativeUrl)
	} else {
		res, continuePagination, err3 := unmarshal(data)
		if err3 != nil {
			return nil, errors.Wrapf(err2, "failed to unmarshal response of indexer %v %v", i.config.Indexer.ION, relativeUrl)
		}
		if continuePagination {
			offset := 0
			if off, hasOffset := params["offset"]; hasOffset {
				offset, _ = strconv.Atoi(off)
			}
			offset += defaultIndexerReqLimit
			params["offset"] = strconv.Itoa(offset)
			nextPage, err := indexerReq[T](ctx, i, relativeUrl, params, unmarshal)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to load page of %v %v (offset %v)", i.config.Indexer.ION, relativeUrl, offset)
			}
			res = append(res, nextPage...)
		}
		return res, nil
	}
}
