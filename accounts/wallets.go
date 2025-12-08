// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) CreateWalletView(ctx context.Context, userID, name string, items []*CoinMapping, symbolGroups []string) (*WalletView, error) {
	missingDefaultCoins := []*coins.Coin{}
	for _, dc := range a.cfg.DefaultCoinsInWalletView {
		defCoins, has := defaultCoins[dc]
		if !has {
			continue
		}
		for _, def := range defCoins {
			if !slices.ContainsFunc(items, func(mapping *CoinMapping) bool { return def.ID == mapping.CoinID }) {
				missingDefaultCoins = append(missingDefaultCoins, def)
			}
		}
	}
	if len(missingDefaultCoins) > 0 {
		for _, def := range missingDefaultCoins {
			matchingItem := &CoinMapping{
				WalletID: nil,
				CoinID:   def.ID,
			}
			items = append(items, matchingItem)
		}
	}
	return a.createWalletView(ctx, userID, name, items, symbolGroups, false)
}

func (a *accounts) createWalletView(ctx context.Context, userID, name string, items []*CoinMapping, symbolGroups []string, main bool) (*WalletView, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	now := time.Now()
	id := uuid.NewString()
	if main {
		id = userID
	}
	params := []any{now, name, userID, symbolGroups, id}
	rowsSql, extraParams := buildInsert(items, 5)
	params = append(params, extraParams...)
	view, err := storage.ExecOne[WalletView](ctx, a.db, fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO wallet_views(created_at, updated_at, name,      user_id, symbol_groups, id,coins) 	
			VALUES  ($1,         $1,         $2,        $3,  $4, $5,     array[%v]::coin_mapping[]   )
			RETURNING * 
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
							  coins.icon_url as iconURL,
                              coins.native
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
			if main {
				wv, _, err := a.GetWalletView(ctx, userID, id)
				return wv, err
			}
			return a.CreateWalletView(ctx, userID, name, items, symbolGroups)
		}
		if storage.IsErr(err, storage.ErrNotFound) {
			wv, _, err := a.GetWalletView(ctx, userID, id)
			return wv, err
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
		view.Aggregation, view.NFTs, _, err = a.fetchWalletInfoForCoins(ctx, userID, view.Coins, view.SymbolGroups)
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
	if len(views) == 0 {
		usr, err := a.getUserByID(ctx, userID)
		if err != nil {
			return nil, errors.Wrapf(err, "user %v is missing default walletview and cannot create due to read user failure", userID)
		}
		wallets, err := a.delegatedRPClient.ListWallets(ctx, userID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get wallets for user %v to detect main", userID)
		}
		var mainWalletID string
		for _, wallet := range wallets {
			if walletID, walletPubKey := dfns.CheckMainWallet(wallet); walletID != "" && walletPubKey != "" {
				mainWalletID = walletID
			}
		}
		var linkDefaultWalletViewToTon bool
		if mainWalletID == "" {
			for _, wallet := range wallets {
				if walletID, walletPubKey := dfns.CheckMainWallet(wallet, "Ton", "TonTestnet"); walletID != "" && walletPubKey != "" {
					mainWalletID = walletID
				}
			}
			if mainWalletID != "" {
				linkDefaultWalletViewToTon = true
			}
		}
		newView, err := a.createDefaultWalletView(ctx, userID, usr.IdentityKeyName, mainWalletID, linkDefaultWalletViewToTon)
		if err != nil {
			return nil, errors.Wrapf(err, "user %v is missing default walletview and cannot create", userID)
		}
		views = append(views, newView)
	}
	return views, nil
}

func (a *accounts) GetWalletView(ctx context.Context, userID, id string) (*WalletView, *string, error) {
	return a.getWalletView(ctx, userID, id, true)
}
func (a *accounts) getWalletView(ctx context.Context, userID, id string, buildCoinsAggregation bool) (*WalletView, *string, error) {
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
						  coins.icon_url as iconURL,
						  coins.native
				   from wallet_views_coinids
				   join coins on wallet_views_coinids.coinid = coins.id) t
			   ) 
		as coins
		from wallet_views WHERE user_id = $1 AND wallet_views.id = $2
	group by created_at, updated_at, name, user_id, symbol_groups, id`, userID, id)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, nil, ErrNotFound
		}

		return nil, nil, errors.Wrapf(err, "failed to get wallet views for user %v", userID)
	}
	if len(views) == 0 {
		return nil, nil, ErrNotFound
	}
	var nextPage *string
	if buildCoinsAggregation {
		views[0].Aggregation, views[0].NFTs, nextPage, err = a.fetchWalletInfoForCoins(ctx, userID, views[0].Coins, views[0].SymbolGroups)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to aggregate walletview coins with wallet data walletview id %v", views[0].ID)
		}
	}
	return views[0], nextPage, nil
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
	var data []byte
	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.Errorf("unexpected type %T for value: %v", value, value)
	}
	err := json.Unmarshal(data, w)
	if err == nil && w != nil && len(*w) > 0 {
		for i, c := range *w {
			if c.Coin != nil {
				var network string
				var priority bool
				network, priority, err = coins.MapNetworkFromCoinGecko(c.Coin.Network, c.Coin.SymbolGroup)
				if err != nil {
					err = errors.Wrapf(err, "failed to map network %v for coin %v", c.Coin.Network, *c.Coin)
					break
				}
				(*w)[i].Coin.Network = network
				(*w)[i].Coin.Prioritized = priority
			}
		}
	}
	return errors.Wrapf(err, "failed to unmarshal value from db %v", value)
}

func (a *accounts) DeleteWalletView(ctx context.Context, userID, id string) error {
	row, err := storage.ExecOne[struct {
		Deleted        bool `db:"deleted"`
		MainWalletView bool `db:"main_wallet_view"`
	}](ctx, a.db,
		`WITH del AS (
				DELETE FROM wallet_views WHERE 
				user_id = $1 AND id = $2 AND
				created_at != (SELECT min(created_at) FROM wallet_views WHERE user_id = $1)
				RETURNING id, user_id
			)
			SELECT del.id IS NOT NULL AS deleted,
		            (wv.created_at = (SELECT min(created_at) FROM wallet_views WHERE user_id = $1)) AS main_wallet_view
			FROM del RIGHT JOIN wallet_views wv 
			ON wv.user_id = $1 and wv.id = $2
			WHERE wv.user_id = $1 and wv.id = $2		
	LIMIT 1`, userID, id)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return ErrNotChanged
		}

		return errors.Wrapf(err, "failed to delete wallet view %v for user %v", id, userID)
	}
	if !row.Deleted && row.MainWalletView {
		return ErrDeleteLast
	}

	return nil
}

func (a *accounts) ModifyWalletView(ctx context.Context, userID, id, newName string, items []*CoinMapping, symbolGroups []string) (*WalletView, error) {
	wv, _, err := a.getWalletView(ctx, userID, id, false)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet view for modification")
	}
	walletForCoin := map[string]*string{}
	for _, extCoin := range wv.Coins {
		walletForCoin[extCoin.CoinID] = extCoin.WalletID
	}
	for i, newCoin := range items {
		if existingWallet, haveExistingWallet := walletForCoin[newCoin.CoinID]; haveExistingWallet && newCoin.WalletID == nil {
			newCoin.WalletID = existingWallet
			items[i] = newCoin
		}
	}
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
							  coins.icon_url as iconURL,
							  coins.native
					   from wallet_views_coinids
					   join coins on wallet_views_coinids.coinid = coins.id) t
				   ) 
			as coins from upd;
	`, itemsSQL), params...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to modify wallet view %v for user %v", id, userID)
	}
	view.Aggregation, view.NFTs, _, err = a.fetchWalletInfoForCoins(ctx, userID, view.Coins, view.SymbolGroups)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to aggregate walletview coins with wallet data walletview id %v", view.ID)
	}
	return view, nil
}

func (a *accounts) fetchWalletInfoForCoins(ctx context.Context, userID string, coinsInWalletView []*CoinMapping, symbolGroups []string) (map[string]*CoinAggregation, []*NFT, *string, error) {
	walletIDs := map[string][]*CoinMapping{}
	groupedBySymbol := make(map[string][]*CoinMapping)
	for _, i := range coinsInWalletView {
		symbol := strings.ToLower(i.Coin.Symbol)
		if symbol == "" {
			symbol = i.Coin.ContractAddress
		}
		if i.WalletID != nil {
			walletIDs[*i.WalletID] = append(walletIDs[*i.WalletID], i)
			if duplSymbol, hasDupl := groupedBySymbol[symbol]; hasDupl {
				for _, dupl := range duplSymbol {
					if dupl.Network == i.Network {
						groupedBySymbol[dupl.ContractAddress] = append(groupedBySymbol[dupl.ContractAddress], dupl)
						delete(groupedBySymbol, symbol)
						symbol = i.Coin.ContractAddress
					}
				}
			}
			groupedBySymbol[symbol] = append(groupedBySymbol[symbol], i)

		}
	}
	coinGroups := make(map[string]*CoinAggregation)
	testNetSymbols := make(map[string]bool)
	allNftsFromWalletView := []*NFT{}
	nextPageVal := make(map[string]string, 0)
	type assetsInfo struct {
		linkedSymbols []*CoinMapping
		assets        *dfns.Assets
		err           error
	}
	type nftInfo struct {
		nfts     []*NFT
		walletID string
		network  string
		nextPage *string
		err      error
	}
	assets := make(chan assetsInfo, len(walletIDs))
	nftInfos := make(chan nftInfo, len(walletIDs))
	var assetsWg, nftsWg sync.WaitGroup
	paginationTokens, limit, err := pagination(ctx)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "malformed pagination tokens %v", userID)
	}
	for walletID, linkedSymbols := range walletIDs {
		assetsWg.Go(func() {
			walletAssets, err := a.GetWalletAssets(ctx, walletID)
			if err != nil {
				assets <- assetsInfo{err: errors.Wrapf(err, "failed to list assets for wallet %v", walletID)}
			}
			assets <- assetsInfo{
				linkedSymbols: linkedSymbols,
				assets:        walletAssets,
			}
		})
		nftsWg.Go(func() {
			p, ok := paginationTokens[walletID]
			if !ok {
				p = "0"
			}
			nfts, network, np, err := a.GetNFTs(ctx, walletID, p, limit)
			nftInfos <- nftInfo{
				nfts:     nfts,
				network:  network,
				nextPage: np,
				walletID: walletID,
				err:      err,
			}
		})
	}
	assetsWg.Wait()
	close(assets)
	nftsWg.Wait()
	close(nftInfos)
	for walletAsset := range assets {
		if walletAsset.err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to fetch wallet assets for user %v", userID)
		}
		walletID := walletAsset.assets.WalletID
		walletAssets := walletAsset.assets
		linkedSymbols := walletAsset.linkedSymbols
		assetsBySymbol := make(map[string]dfns.Asset)
		for _, asset := range walletAssets.Assets {
			symbolI, hasSymbol := asset["symbol"]
			contractI, hasContract := asset["contract"]
			nativeCoin := asset["kind"] == "Native"
			if hasSymbol {
				symbol := strings.ToLower(symbolI.(string))
				if symbol == "ice" && (nativeCoin || strings.EqualFold(walletAssets.Network, "ion")) {
					symbol = "ion"
				}
				// Testnet, i.e SepoliaETH, coin gecko dont provide testnet symbol
				if nativeCoin {
					_, testnetSymbol := testNetSymbols[symbol]
					_, validSymbol := groupedBySymbol[symbol]
					if !validSymbol || testnetSymbol {
						testNetSymbols[symbol] = true
						if len(linkedSymbols) == 1 && strings.EqualFold(walletAssets.Network, linkedSymbols[0].Network) && linkedSymbols[0].Native {
							groupedBySymbol[symbol] = append(groupedBySymbol[symbol], linkedSymbols[0])
						} else if len(linkedSymbols) > 0 {
							for _, ls := range linkedSymbols {
								if ls.Native && strings.EqualFold(walletAssets.Network, ls.Network) {
									groupedBySymbol[symbol] = append(groupedBySymbol[symbol], ls)
									break
								}
							}
						}
					}
				}
				assetsBySymbol[symbol] = asset
				if hasContract {
					if coins.IsTestnet(walletAssets.Network) && strings.ToLower(symbol) == "snow" {
						assetsBySymbol["0xd1f3d2f5c12a205fc912358878b089eae48a557f"] = asset
					}
					assetsBySymbol[contractI.(string)] = asset
				}
			}
		}
		for searchSymbol, group := range groupedBySymbol {
			asset, hasAsset := assetsBySymbol[searchSymbol]
			if hasAsset {
				symbolI, hasSymbol := asset["symbol"]
				symbol := searchSymbol
				if hasSymbol {
					symbol = strings.ToLower(symbolI.(string))
					if symbol == "ice" && (strings.EqualFold(searchSymbol, "ion")) {
						symbol = "ion"
					}
				}
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
						if strBalance, isStr := asset["balance"].(string); isStr {
							assetVal.SetString(strBalance, 10)
						} else if floatBalance, isFloat := asset["balance"].(float64); isFloat {
							assetVal.SetInt64(int64(floatBalance))
						}
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
			} else if _, hasCoin := coinGroups[searchSymbol]; !hasAsset && !hasCoin {
				coinGroups[searchSymbol] = &CoinAggregation{
					TotalBalance: big.NewInt(0),
					Wallets:      make([]*CoinInWallet, 0),
				}
			}
		}
	}

	for ni := range nftInfos {
		err = ni.err
		if err != nil {
			if delegatedErr := ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
				var delegatedParsedErr *DelegatedRelyingPartyErr
				if errors.As(delegatedErr, &delegatedParsedErr) {
					if delegatedParsedErr.HTTPStatus == http.StatusBadRequest && strings.Contains(delegatedParsedErr.Message, "does not support NFT balances") {
						continue
					}
				}
			}
			return nil, nil, nil, errors.Wrapf(err, "failed to get nfts for wallet %v (wallet view aggregation)", ni.walletID)
		}
		np := ni.nextPage
		if np != nil {
			nextPageVal[ni.walletID] = *np
		}
		for _, n := range ni.nfts {
			n.WalletID = ni.walletID
			n.Network = ni.network
			allNftsFromWalletView = append(allNftsFromWalletView, n)
		}
	}

	var nextPage *string
	if len(nextPageVal) > 0 {
		b, _ := json.Marshal(nextPageVal)
		str := base64.StdEncoding.EncodeToString(b)
		nextPage = &str
	}
	return coinGroups, allNftsFromWalletView, nextPage, nil
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
	res := make([]*CoinWithWalletInfo, 0, len(listCoins))
	for _, c := range listCoins {
		walletMatched := false
		for _, wallet := range allWallets {
			walletID := wallet["id"].(string)
			walletNetwork := strings.ToLower(wallet["network"].(string))
			if _, has := wallets[walletID]; (has || hasAllWallets) && c.Network == walletNetwork {
				wallets[walletID] = wallet
				coinsByNetwork[walletNetwork] = c
				walletMatched = true
			}
		}
		if !walletMatched {
			res = append(res, &CoinWithWalletInfo{
				Coin:          c,
				WalletID:      nil,
				WalletAddress: nil,
				Balance:       "0",
			})
		}
	}
	for walletID, wallet := range wallets {
		reqCtx := context.WithValue(ctx, "walletNetwork", wallet["network"])
		reqCtx = context.WithValue(reqCtx, "walletAddress", wallet["address"])
		walletAssets, err := a.GetWalletAssets(reqCtx, walletID)
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
				walletAddr := wallet["address"].(string)
				res = append(res, &CoinWithWalletInfo{
					Coin:          coin,
					WalletID:      &walletID,
					WalletAddress: &walletAddr,
					Balance:       asset["balance"].(string),
				})
			}
		}
	}
	slices.SortFunc(res, func(a, b *CoinWithWalletInfo) int {
		balanceA := new(big.Int)
		var ok bool
		balanceA, ok = balanceA.SetString(a.Balance, 10)
		if !ok {
			return 0
		}
		balanceB := new(big.Int)
		balanceB, ok = balanceB.SetString(b.Balance, 10)
		if !ok {
			return 0
		}
		return balanceA.Cmp(balanceB)
	})
	return res, nil
}

func (a *accounts) GetNFTs(ctx context.Context, walletID, paginationToken string, limit uint64) (nftResp []*NFT, walletNetwork string, newPaginationToken *string, err error) {
	newPaginationToken = nil
	nfts, err := a.delegatedRPClient.ListNFTs(ctx, walletID)
	if err != nil {
		if delegatedErr := ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
			var delegatedParsedErr *DelegatedRelyingPartyErr
			if errors.As(delegatedErr, &delegatedParsedErr) {
				if delegatedParsedErr.HTTPStatus == http.StatusBadRequest && strings.Contains(delegatedParsedErr.Message, dfns.ErrMessageNFTNotSupported) &&
					(strings.Contains(delegatedParsedErr.Message, dfns.DefaultWalletNetworkMainNet) || strings.Contains(delegatedParsedErr.Message, dfns.DefaultWalletNetworkTestNet)) {
					var w *dfns.Wallet
					w, err = a.delegatedRPClient.GetWallet(ctx, walletID)
					if err != nil {
						return nil, "", nil, errors.Wrapf(err, "failed to get wallet %v", walletID)
					}
					var nftsList []coins.WalletNFT
					nftsList, newPaginationToken, err = a.indexer.ListNFTs(ctx, (*w)["address"].(string), paginationToken, limit)
					nfts = &dfns.NFTs{
						NFTs:     nftsList,
						Network:  (*w)["network"].(string),
						WalletID: walletID,
					}
				}
			}
		}
		if err != nil {
			return nil, "", nil, errors.Wrapf(err, "failed to get nfts from delegatedRP 3rd party")
		}
	}
	populatedNFTs, err := a.coinsRepo.ImportNFTs(ctx, nfts.Network, nfts.NFTs)
	if err != nil {
		return nil, "", nil, errors.Wrapf(err, "failed to import extra data for nfts")
	}
	return populatedNFTs, nfts.Network, newPaginationToken, nil
}

func (a *accounts) CreateWalletForWalletView(ctx context.Context, userID, network, walletViewID string) (*Wallet, error) {
	walletView, _, err := a.getWalletView(ctx, userID, walletViewID, false)
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
		nativeCoin, err := a.coinsRepo.GetNativeCoinForNetwork(ctx, network)
		if err != nil {
			if errors.Is(err, coins.ErrNotFound) {
				err = nil
			}
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get native coin for network %v", network)
			}
		}
		if nativeCoin == nil {
			return nil, ErrWalletLinked
		}
		containsNativeCoin := false
		for _, item := range walletView.Coins {
			if item.Coin.ID == nativeCoin.ID {
				containsNativeCoin = true
				break
			}
		}
		if containsNativeCoin {
			return nil, ErrWalletLinked
		}
		walletView.Coins = append(walletView.Coins, &CoinMapping{
			WalletID: nil,
			CoinID:   nativeCoin.ID,
		})
		walletView.SymbolGroups = append(walletView.SymbolGroups, nativeCoin.SymbolGroup)
		targetCoins = append(targetCoins, len(walletView.Coins)-1)
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

func (a *accounts) FetchMainWallet(ctx context.Context, masterKey string) (Wallet, error) {
	usr, err := a.getUserByID(ctx, masterKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to match user by master key %v", masterKey)
	}
	userWallets, err := a.delegatedRPClient.ListWallets(ctx, usr.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to wallet list for user %v", usr.ID)
	}
	var mainWallet Wallet
	for _, wallet := range userWallets {
		if walletID, walletPubKey := dfns.CheckMainWallet(wallet); walletID != "" && walletPubKey != "" {
			mainWallet = wallet
			break
		}
	}
	return mainWallet, nil
}

func pagination(ctx context.Context) (map[string]string, uint64, error) {
	if lim := ctx.Value("paginationLimit"); lim != nil {
		paginationLimit := lim.(uint64)
		if tok := ctx.Value("paginationToken"); tok != nil {
			str := tok.(string)
			if str == "" {
				return map[string]string{}, paginationLimit, nil
			}
			b, err := base64.StdEncoding.DecodeString(str)
			if err != nil {
				return nil, 0, errors.Wrapf(err, "failed to unmarshal pagination token: %v", tok)
			}
			var byWallet map[string]string
			if err = json.Unmarshal(b, &byWallet); err != nil {
				return nil, 0, errors.Wrapf(err, "failed to unmarshal pagination token: %v", tok)
			}
			return byWallet, paginationLimit, nil
		} else {
			return map[string]string{}, paginationLimit, nil
		}
	}
	return map[string]string{}, 100, nil
}

func (a *accounts) GetWalletHistory(ctx context.Context, walletID, paginationToken string, limit uint64) ([]WalletHistoryItem, string, *string, error) {
	wallet, err := a.delegatedRPClient.GetWallet(ctx, walletID)
	if err != nil {
		return nil, "", nil, errors.Wrapf(err, "failed to get wallet %v", walletID)
	}
	network := (*wallet)["network"].(string)
	if strings.EqualFold(network, dfns.DefaultWalletNetworkTestNet) || strings.EqualFold(network, dfns.DefaultWalletNetworkMainNet) {
		walletAddress := (*wallet)["address"].(string)
		transaction, newPagination, err := a.indexer.WalletTransactions(ctx, walletID, walletAddress, paginationToken, limit)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to get wallet history for wallet %v %v from indexer, getting from 3rdparty", walletID, walletAddress))
			history, err := a.delegatedRPClient.GetWalletHistory(ctx, walletID, paginationToken, limit)
			if err != nil {
				return nil, "", nil, errors.Wrapf(err, "failed to get wallet history for wallet %v both from indexer and 3rdparty", walletID)
			}
			return history.Items, history.Network, history.NextPageToken, nil
		}
		return transaction, network, newPagination, nil
	}
	history, err := a.delegatedRPClient.GetWalletHistory(ctx, walletID, paginationToken, limit)
	if err != nil {
		return nil, "", nil, errors.Wrapf(err, "failed to get wallet history for wallet %v", walletID)
	}
	return history.Items, history.Network, history.NextPageToken, nil
}

func (a *accounts) GetWalletAssets(ctx context.Context, walletID string) (*Assets, error) {
	walletNetwork := ""
	walletAddress := ""
	if ctxNetwork := ctx.Value("wallet"); ctxNetwork != nil { // We already fetched if while building wallet view
		walletNetwork = ctxNetwork.(string)
		if addr := ctx.Value("walletAddress"); addr != nil {
			walletAddress = addr.(string)
		}
	}
	if walletNetwork == "" || walletAddress == "" {
		wallet, err := a.delegatedRPClient.GetWallet(ctx, walletID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get wallet %v", walletID)
		}
		walletNetwork = (*wallet)["network"].(string)
		walletAddress = (*wallet)["address"].(string)
	}
	if strings.EqualFold(walletNetwork, dfns.DefaultWalletNetworkTestNet) || strings.EqualFold(walletNetwork, dfns.DefaultWalletNetworkMainNet) {
		assets, err := a.indexer.GetBalance(ctx, walletAddress)
		if err != nil {
			log.Error(errors.Wrapf(err, "indexer call failed for fwtching balance for wallet %v %v, getting from 3rd party", walletID, walletAddress))
			return a.delegatedRPClient.ListAssets(ctx, walletID)
		}
		return &Assets{
			Assets:   assets,
			Network:  walletNetwork,
			WalletID: walletID,
		}, nil
	}
	return a.delegatedRPClient.ListAssets(ctx, walletID)
}
