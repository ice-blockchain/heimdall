// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) CreateWalletView(ctx context.Context, userID, name string, items []*CoinMapping, symbolGroups []string) (*WalletView, error) {
	now := time.Now()
	params := []any{now, name, userID, symbolGroups}
	rowsSql, extraParams := buildInsert(items, 4)
	params = append(params, extraParams...)
	rows, err := storage.Exec(ctx, a.db, fmt.Sprintf(`INSERT INTO wallet_views(created_at, updated_at, name,      user_id, symbol_groups, coins) 
															VALUES  ($1,         $1,         $2,        $3,  $4,     array[%v]    );`, rowsSql),
		params...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.Wrap(err, "failed to create wallet view")
	}
	if rows == 0 {
		return nil, errors.Errorf("failed to create wallet view, unexpected rows count %v", rows)
	}

	return &WalletView{
		Name:         name,
		Coins:        items,
		CreatedAt:    now,
		UpdatedAt:    now,
		UserID:       userID,
		SymbolGroups: symbolGroups,
	}, nil
}
func (a *accounts) GetWalletViews(ctx context.Context, userID string) ([]*WalletView, error) {
	views, err := storage.Select[WalletView](ctx, a.db, `SELECT 
    created_at, updated_at, name, user_id, array_to_json(coins) as coins, symbol_groups
    FROM wallet_views WHERE user_id = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet views for user %v", userID)
	}

	return views, nil
}

func buildInsert(items []*CoinMapping, nextIndex int) (string, []any) {
	rows := make([]string, 0, len(items))
	params := make([]any, 0, len(items)*2)
	for _, i := range items {
		rows = append(rows, fmt.Sprintf("row($%v,$%v)::coin_mapping", nextIndex+1, nextIndex+2))
		params = append(params, i.CoinID, i.WalletID)
		nextIndex += 2
	}

	return strings.Join(rows, ","), params
}

func (w *CoinMappings) Scan(value any) error {
	return errors.Wrapf(json.Unmarshal([]byte((value.(string))), w), "failed to unmarshal value from db %v", value)
}

func (a *accounts) DeleteWalletView(ctx context.Context, userID, name string) error {
	row, err := storage.ExecOne[struct {
		Deleted bool `db:"deleted"`
		HasMore bool `db:"has_more"`
	}](ctx, a.db,
		`WITH del AS (
				DELETE FROM wallet_views WHERE user_id = $1 AND name = $2 AND EXISTS(SELECT 1 FROM wallet_views WHERE user_id = $1 AND name != $2) RETURNING name
			)
			SELECT del.name IS NOT NULL AS deleted, (wv.name is not null AND wv.name!=$2) AS has_more  FROM del RIGHT JOIN wallet_views wv 
			ON wv.user_id = $1
			WHERE wv.user_id = $1			
LIMIT 1`, userID, name)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return ErrNotChanged
		}

		return errors.Wrapf(err, "failed to delete wallet view %v for user %v", name, userID)
	}
	if !row.Deleted && row.HasMore {
		return ErrNotChanged
	}
	if !row.Deleted && !row.HasMore {
		return ErrDeleteLast
	}

	return nil
}

func (a *accounts) ModifyWalletView(ctx context.Context, userID, name, newName string, items []*CoinMapping, symbolGroups []string) (*WalletView, error) {
	now := time.Now()
	params := []any{userID, name, newName, now, symbolGroups}
	itemsSQL, extraParams := buildInsert(items, 5)
	params = append(params, extraParams...)
	view, err := storage.ExecOne[WalletView](ctx, a.db, fmt.Sprintf(`UPDATE wallet_views 
	SET 
	    name = $3,
		coins = array[%v],
		updated_at = $4,
	    symbol_groups = $5
	WHERE user_id = $1 AND name = $2 RETURNING created_at, updated_at, name, user_id, array_to_json(coins) as coins, symbol_groups`, itemsSQL), params...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to modify wallet view %v for user %v", name, userID)
	}

	return view, nil
}

func (a *accounts) GetCoinsOfSymbolGroup(ctx context.Context, userID, symbolGroup string) ([]*CoinWithWalletInfo, error) {
	views, err := storage.Select[WalletView](ctx, a.db, `SELECT 
    created_at, updated_at, name, user_id, array_to_json(coins) as coins
    FROM wallet_views WHERE user_id = $1 AND symbol_groups @> ARRAY[$2]`, userID, symbolGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet views for user %v", userID)
	}
	hasAllWallets := false
	wallets := map[string]dfns.Wallet{}
	for _, v := range views {
		for _, walletCoinMapping := range v.Coins {
			if walletCoinMapping.WalletID == nil {
				hasAllWallets = true
				break
			}
			wallets[*walletCoinMapping.WalletID] = nil
		}
	}
	allWallets, err := a.delegatedRPClient.ListWallets(ctx, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list all wallets for user %v", userID)
	}
	listCoins, err := a.coinsRepo.GetCoinsOfSymbolGroup(ctx, []string{symbolGroup})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get coins of symbol group %v", symbolGroup)
	}
	coinsByNetwork := map[string]*coins.Coin{}
	for _, c := range listCoins {
		for _, wallet := range allWallets {
			walletID := wallet["id"].(string)
			walletNetwork := wallet["network"].(string)
			if _, has := wallets[walletID]; (has || hasAllWallets) && c.Network == walletNetwork {
				wallets[walletID] = wallet
				coinsByNetwork[walletNetwork] = c
			}
		}
	}
	res := make([]*CoinWithWalletInfo, 0, len(coinsByNetwork))
	for walletID, wallet := range wallets {
		walletAssets, err := a.delegatedRPClient.ListAssets(ctx, walletID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list assets for wallet %v", walletID)
		}
		for _, asset := range walletAssets.Assets {
			coin, hasCoin := coinsByNetwork[walletAssets.Network]
			if !hasCoin {
				continue
			}
			assetContract := asset["contract"]
			if assetContract == coin.ContractAddress {
				res = append(res, &CoinWithWalletInfo{
					Coin:          coin,
					WalletID:      walletID,
					WalletAddress: wallet["address"].(string),
					Balance:       asset["balance"].(string),
				})
			}
		}
	}
	return res, nil
}

func (a *accounts) GetNFTs(ctx context.Context, walletID string) ([]*NFT, string, error) {
	nfts, err := a.delegatedRPClient.ListNFTs(ctx, walletID)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to get nfts from delegatedRP 3rd party")
	}
	populatedNFTs, err := a.coinsRepo.ImportNFTs(ctx, nfts.Network, nfts.NFTs)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to import extra data for nfts")
	}
	return populatedNFTs, nfts.Network, nil
}
