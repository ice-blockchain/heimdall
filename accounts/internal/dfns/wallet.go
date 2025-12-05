// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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
	resp, err := dfnsCall[struct{}, Assets](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v/assets", walletID), header, []int{http.StatusNotFound})
	if err != nil {
		if delegatedErr := ParseErrAsDfnsInternalErr(err); delegatedErr != nil {
			var delegatedParsedErr *DfnsInternalError
			if errors.As(delegatedErr, &delegatedParsedErr) && delegatedParsedErr.HTTPStatus == http.StatusNotFound &&
				strings.Contains(delegatedParsedErr.Message, "Can't complete the action because account") && strings.Contains(delegatedParsedErr.Message, "doesn't exist") {
				var wallet *Wallet
				wallet, err = c.GetWallet(ctx, walletID)
				if err != nil {
					return nil, errors.Wrap(err, "near network, not existed account yet and failed to get wallet")
				}
				resp = &Assets{
					Assets:   nil,
					Network:  (*wallet)["network"].(string),
					WalletID: walletID,
				}
			}

		}
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list assets on wallet %v", walletID)
		}
	}

	return resp, nil
}

func (c *dfnsClient) ListNFTs(ctx context.Context, walletID string) (*NFTs, error) {
	header := http.Header{}
	resp, err := dfnsCall[struct{}, NFTs](ctx, c, nil, "GET", fmt.Sprintf("/wallets/%v/nfts", walletID), header, []int{http.StatusBadRequest})
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

func (c *dfnsClient) GetWalletHistory(ctx context.Context, walletID, paginationToken string, limit uint64) (*WalletHistory, error) {
	header := http.Header{}
	header.Add(authDfnsHeader, dfnsAuthHeader(ctx))
	resp, err := dfnsCall[struct {
		PaginationToken string `form:"paginationToken"`
		Limit           uint64 `form:"limit"`
	}, WalletHistory](ctx, c, &struct {
		PaginationToken string `form:"paginationToken"`
		Limit           uint64 `form:"limit"`
	}{
		PaginationToken: paginationToken,
		Limit:           limit,
	}, "GET", fmt.Sprintf("/wallets/%v/history", walletID), header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list NFTs on wallet %v", walletID)
	}

	return resp, nil
}
