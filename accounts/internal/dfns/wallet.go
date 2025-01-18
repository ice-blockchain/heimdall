// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func (c *dfnsClient) ListWallets(ctx context.Context, userID string) ([]Wallet, error) {
	header := http.Header{}
	wallets := make([]Wallet, 0)
	params := struct {
		OwnerID string `form:"ownerId"`
	}{
		OwnerID: userID,
	}
	resp, err := dfnsCall[struct {
		OwnerID string `form:"ownerId"`
	}, page[Wallet]](ctx, c, &params, "GET", "/wallets", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list wallets for %v", userID)
	}
	nextPageToken := resp.NextPageToken
	wallets = append(wallets, resp.Items...)
	for nextPageToken != nil && *nextPageToken != "" {
		resp, err = dfnsCall[struct {
			OwnerID         string `form:"ownerId"`
			PaginationToken string `form:"paginationToken"`
		}, page[Wallet]](ctx, c, &struct {
			OwnerID         string `form:"ownerId"`
			PaginationToken string `form:"paginationToken"`
		}{
			OwnerID:         userID,
			PaginationToken: *nextPageToken,
		}, "GET", "/wallets/", header)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list wallets for %v (pagination %v)", userID, *nextPageToken)
		}
		wallets = append(wallets, resp.Items...)
		nextPageToken = resp.NextPageToken
	}

	return wallets, nil
}

func (c *dfnsClient) ListAssets(ctx context.Context, walletID string) (*Assets, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, Assets](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v/assets", walletID), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list assets on wallet %v", walletID)
	}

	return resp, nil
}

func (c *dfnsClient) ListNFTs(ctx context.Context, walletID string) (*NFTs, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, NFTs](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v/nfts", walletID), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list NFTs on wallet %v", walletID)
	}

	return resp, nil
}

func (c *dfnsClient) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, Wallet](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v", walletID), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet %v", walletID)
	}

	return resp, nil
}

func (c *dfnsClient) CreateWallet(ctx context.Context, network, name string) (*Wallet, error) {
	header := http.Header{}
	header.Add(authDfnsHeader, dfnsAuthHeader(ctx))
	header.Add(userActionDfnsHeader, dfnsUserActionHeader(ctx))
	header.Add(appIDHeader, appID(ctx))
	resp, err := dfnsCall[struct {
		Network string `json:"network"`
		Name    string `json:"name"`
	}, Wallet](ctx, c, &struct {
		Network string `json:"network"`
		Name    string `json:"name"`
	}{Network: network, Name: name}, "POST", "/wallets", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to creare wallet %v in %v", name, network)
	}

	return resp, nil
}
