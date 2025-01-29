// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) CreateWalletView(ctx context.Context, userID, name string, items []*CoinMapping, symbolGroups []string) (*WalletView, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	now := time.Now()
	id := uuid.NewString()
	params := []any{now, name, userID, symbolGroups, id}
	rowsSql, extraParams := buildInsert(items, 5)
	params = append(params, extraParams...)
	view, err := storage.ExecOne[WalletView](ctx, a.db, fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO wallet_views(created_at, updated_at, name,      user_id, symbol_groups, id,coins) 	
			VALUES  ($1,         $1,         $2,        $3,  $4, $5,     array[%v]::coin_mapping[]   ) RETURNING * 
		)
		SELECT created_at, updated_at, name, user_id, symbol_groups, id,
				   (SELECT json_agg(row_to_json(t.*)) from (
					   WITH wallet_views_coinids as (
						   (SELECT ins.*, (unnest(ins.coins)::coin_mapping).coinId, (unnest(ins.coins)::coin_mapping).walletid
							from ins WHERE user_id = $3 AND ins.id = $5)
					   )
					   select wallet_views_coinids.walletid,wallet_views_coinids.coinid,
							  coins.decimals,
							  coins.version,
							  coins.price_usd as priceUSD,
							  coins.id,
							  coins.network,
							  coins.name,
							  coins.contract_address as contractAddress,
							  coins.symbol,
							  coins.symbol_group as symbolGroup,
							  coins.icon_url as iconURL
					   from wallet_views_coinids
					   join coins on wallet_views_coinids.coinid = coins.id) t
				   ) 
			as coins from ins;`, rowsSql),
		params...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			return nil, ErrNotFound
		}
		if storage.IsErr(err, storage.ErrDuplicate) {
			return a.CreateWalletView(ctx, userID, name, items, symbolGroups)
		}
		return nil, errors.Wrap(err, "failed to create wallet view")
	}
	hasWallets := false
	for _, c := range items {
		if c.WalletID != nil {
			hasWallets = true
		}
	}
	if hasWallets {
		view.Aggregation, err = a.fetchWalletInfoForCoins(ctx, userID, view.Coins, view.SymbolGroups)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to aggregate walletview coins with wallet data walletview id %v on creation", view.ID)
		}
	}

	return view, nil
}
func (a *accounts) GetWalletViews(ctx context.Context, userID string) ([]*WalletView, error) {
	views, err := storage.Select[WalletView](ctx, a.db, `SELECT 
    created_at, updated_at, name, user_id, array_to_json(coins) as coins, symbol_groups, id
    FROM wallet_views WHERE user_id = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet views for user %v", userID)
	}

	return views, nil
}

func (a *accounts) GetWalletView(ctx context.Context, userID, id string) (*WalletView, error) {
	return a.getWalletView(ctx, userID, id, true)
}
func (a *accounts) getWalletView(ctx context.Context, userID, id string, buildCoinsAggregation bool) (*WalletView, error) {
	// Merge coinId from wallet_views.coins and coins entry and collapse to json array
	views, err := storage.Select[WalletView](ctx, a.db, `
		SELECT created_at, updated_at, name, user_id, symbol_groups, id,
			   (SELECT json_agg(row_to_json(t.*)) from (
				   WITH wallet_views_coinids as (
					   (SELECT wallet_views.*, (unnest(wallet_views.coins)::coin_mapping).coinId, (unnest(wallet_views.coins)::coin_mapping).walletid
					    from wallet_views WHERE user_id = $1 AND wallet_views.id = $2)
				   )
				   select wallet_views_coinids.walletid,wallet_views_coinids.coinid,
						  coins.decimals,
						  coins.version,
						  coins.price_usd as priceUSD,
						  coins.id,
						  coins.network,
						  coins.name,
						  coins.contract_address as contractAddress,
						  coins.symbol,
						  coins.symbol_group as symbolGroup,
						  coins.icon_url as iconURL
				   from wallet_views_coinids
				   join coins on wallet_views_coinids.coinid = coins.id) t
			   ) 
		as coins
		from wallet_views WHERE user_id = $1 AND wallet_views.id = $2
	group by created_at, updated_at, name, user_id, symbol_groups, id`, userID, id)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrapf(err, "failed to get wallet views for user %v", userID)
	}
	if len(views) == 0 {
		return nil, ErrNotFound
	}
	if buildCoinsAggregation {
		views[0].Aggregation, err = a.fetchWalletInfoForCoins(ctx, userID, views[0].Coins, views[0].SymbolGroups)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to aggregate walletview coins with wallet data walletview id %v", views[0].ID)
		}
	}
	return views[0], nil
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
	if value == nil {
		*w = CoinMappings([]*CoinMapping{})
		return nil
	}
	err := json.Unmarshal([]byte((value.(string))), w)
	if err == nil && w != nil && len(*w) > 0 {
		for i, c := range *w {
			if c.Coin != nil {
				var network string
				network, err = coins.MapNetworkFromCoinGecko(c.Coin.Network)
				if err != nil {
					err = errors.Wrapf(err, "failed to map network %v for coin %v", c.Coin.Network, *c.Coin)
					break
				}
				(*w)[i].Coin.Network = network
			}
		}
	}
	return errors.Wrapf(err, "failed to unmarshal value from db %v", value)
}

func (a *accounts) DeleteWalletView(ctx context.Context, userID, id string) error {
	row, err := storage.ExecOne[struct {
		Deleted        bool `db:"deleted"`
		HasMore        bool `db:"has_more"`
		RestrictedCoin bool `db:"restricted_coin"`
	}](ctx, a.db,
		fmt.Sprintf(`WITH del AS (
				DELETE FROM wallet_views WHERE 
				user_id = $1 AND id = $2 AND
				EXISTS(SELECT 1 FROM wallet_views WHERE user_id = $1 AND id != $2) AND
                NOT EXISTS(SELECT 1 FROM unnest(wallet_views.coins) AS c  WHERE c.coinId = '%[1]v')  RETURNING id
			)
			SELECT del.id IS NOT NULL AS deleted,
		            (wv.name is not null AND wv.id!=$2) AS has_more,
					EXISTS(SELECT 1 FROM unnest(wv.coins) AS c WHERE c.coinId = '%[1]v') as restricted_coin
			FROM del RIGHT JOIN wallet_views wv 
			ON wv.user_id = $1
			WHERE wv.user_id = $1			
	LIMIT 1`, defaultWalletViewCoinID), userID, id)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return ErrNotChanged
		}

		return errors.Wrapf(err, "failed to delete wallet view %v for user %v", id, userID)
	}
	if !row.Deleted && row.RestrictedCoin {
		return ErrDeleteLast
	}
	if !row.Deleted && row.HasMore {
		return ErrNotChanged
	}
	if !row.Deleted && !row.HasMore {
		return ErrDeleteLast
	}

	return nil
}

func (a *accounts) ModifyWalletView(ctx context.Context, userID, id, newName string, items []*CoinMapping, symbolGroups []string) (*WalletView, error) {
	now := time.Now()
	params := []any{userID, id, newName, now, symbolGroups}
	itemsSQL, extraParams := buildInsert(items, 5)
	params = append(params, extraParams...)
	view, err := storage.ExecOne[WalletView](ctx, a.db, fmt.Sprintf(`
		WITH upd AS (
			UPDATE wallet_views 
				SET 
					name = $3,
					coins = array[%v]::coin_mapping[],
					updated_at = $4,
					symbol_groups = $5
				WHERE user_id = $1 AND id = $2 RETURNING *
		) SELECT
		created_at, updated_at, name, user_id, symbol_groups, id,
				   (SELECT json_agg(row_to_json(t.*)) from (
					   WITH wallet_views_coinids as (
						   (SELECT upd.*, (unnest(upd.coins)::coin_mapping).coinId, (unnest(upd.coins)::coin_mapping).walletid
							from upd WHERE user_id = $1 AND upd.id = $2)
					   )
					   select wallet_views_coinids.walletid,wallet_views_coinids.coinid,
							  coins.decimals,
							  coins.version,
							  coins.price_usd as priceUSD,
							  coins.id,
							  coins.network,
							  coins.name,
							  coins.contract_address as contractAddress,
							  coins.symbol,
							  coins.symbol_group as symbolGroup,
							  coins.icon_url as iconURL
					   from wallet_views_coinids
					   join coins on wallet_views_coinids.coinid = coins.id) t
				   ) 
			as coins from upd;
	`, itemsSQL), params...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to modify wallet view %v for user %v", id, userID)
	}
	view.Aggregation, err = a.fetchWalletInfoForCoins(ctx, userID, view.Coins, view.SymbolGroups)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to aggregate walletview coins with wallet data walletview id %v", view.ID)
	}
	return view, nil
}

func (a *accounts) fetchWalletInfoForCoins(ctx context.Context, userID string, coins []*CoinMapping, symbolGroups []string) (map[string]*CoinAggregation, error) {
	walletIDs := map[string][]*CoinMapping{}
	groupedBySymbol := make(map[string][]*CoinMapping)
	for _, i := range coins {
		symbol := strings.ToLower(i.Coin.Symbol)
		if i.WalletID != nil {
			walletIDs[*i.WalletID] = append(walletIDs[*i.WalletID], i)
			groupedBySymbol[symbol] = append(groupedBySymbol[symbol], i)
		}
	}
	coinGroups := make(map[string]*CoinAggregation)
	for walletID, linkedSymbols := range walletIDs {
		walletAssets, err := a.delegatedRPClient.ListAssets(ctx, walletID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list assets for wallet %v", walletID)
		}
		assetsBySymbol := make(map[string]dfns.Asset)
		for _, asset := range walletAssets.Assets {
			symbolI, hasSymbol := asset["symbol"]
			nativeCoin := asset["kind"] == "Native"
			if hasSymbol {
				symbol := strings.ToLower(symbolI.(string))
				// Testnet, i.e SepoliaETH, coin gecko dont provide testnet symbol
				if _, validSymbol := groupedBySymbol[symbol]; nativeCoin && !validSymbol {
					if len(linkedSymbols) == 1 {
						groupedBySymbol[symbol] = append(groupedBySymbol[symbol], linkedSymbols[0])
					} else if len(linkedSymbols) > 0 {
						for _, ls := range linkedSymbols {
							if ls.ContractAddress == "" {
								groupedBySymbol[symbol] = append(groupedBySymbol[symbol], ls)
								break
							}
						}
					}
				}
				assetsBySymbol[symbol] = asset
			}
		}
		for symbol, group := range groupedBySymbol {
			asset, hasAsset := assetsBySymbol[symbol]
			if hasAsset {
				for _, g := range group {
					if g.WalletID == nil || *g.WalletID == walletID {
						coin, hasCoin := coinGroups[symbol]
						if !hasCoin {
							coin = &CoinAggregation{
								TotalBalance: new(big.Int),
								Wallets:      make([]*CoinInWallet, 0),
							}
						}
						assetVal := new(big.Int)
						assetVal.SetString(asset["balance"].(string), 10)
						coin.TotalBalance = coin.TotalBalance.Add(coin.TotalBalance, assetVal)
						coin.Wallets = append(coin.Wallets, &CoinInWallet{
							WalletID: walletAssets.WalletID,
							Network:  walletAssets.Network,
							CoinID:   g.CoinID,
							Asset:    &asset,
						})
						coinGroups[symbol] = coin
					}
				}
			} else if _, hasCoin := coinGroups[symbol]; !hasAsset && !hasCoin {
				coinGroups[symbol] = &CoinAggregation{
					TotalBalance: big.NewInt(0),
					Wallets:      make([]*CoinInWallet, 0),
				}
			}
		}
	}

	return coinGroups, nil
}

func (a *accounts) GetCoinsOfSymbolGroup(ctx context.Context, userID, symbolGroup string) ([]*CoinWithWalletInfo, error) {
	views, err := storage.Select[WalletView](ctx, a.db, `SELECT 
    created_at, updated_at, name, user_id, array_to_json(coins) as coins, symbol_groups, id
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
			walletNetwork := strings.ToLower(wallet["network"].(string))
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
			coin, hasCoin := coinsByNetwork[strings.ToLower(walletAssets.Network)]
			if !hasCoin {
				continue
			}
			assetContract := asset["contract"]
			assetSymbol := asset["symbol"].(string)
			isNativeCoin := asset["kind"] == "Native"
			if assetContract == coin.ContractAddress ||
				(coins.IsTestnet(walletAssets.Network) && strings.EqualFold(assetSymbol, coin.Symbol)) ||
				(coins.IsTestnet(walletAssets.Network) && isNativeCoin && coin.ContractAddress == "" && strings.EqualFold(walletAssets.Network, coin.Network)) {
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

func (a *accounts) CreateWalletForWalletView(ctx context.Context, userID, network, walletViewID string) (*Wallet, error) {
	walletView, err := a.getWalletView(ctx, userID, walletViewID, false)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet view %v for wallet creation on %v", walletViewID, network)
	}
	targetCoins := []int{}
	for i, item := range walletView.Coins {
		if item.Coin == nil {
			continue
		}
		if strings.EqualFold(network, item.Coin.Network) && item.WalletID == nil {
			targetCoins = append(targetCoins, i)
		}
	}
	if len(targetCoins) == 0 {
		return nil, ErrWalletLinked
	}
	wallet, err := a.delegatedRPClient.CreateWallet(ctx, network, walletView.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create wallet %v on %v for user %v", walletView.ID, network, userID)
	}
	walletID := (*wallet)["id"].(string)
	for _, idx := range targetCoins {
		walletView.Coins[idx] = &CoinMapping{
			WalletID: &walletID,
			CoinID:   walletView.Coins[idx].CoinID,
		}
	}
	_, err = a.ModifyWalletView(ctx, userID, walletViewID, walletView.Name, walletView.Coins, walletView.SymbolGroups)

	return wallet, errors.Wrapf(err, "failed to modify walletview after wallet creation")
}
