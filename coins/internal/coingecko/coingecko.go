// SPDX-License-Identifier: ice License 1.0

package coingecko

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	stdlibtime "time"

	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"
	"github.com/pkg/errors"
	"github.com/twilio/twilio-go/client/form"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func New(applicationYamlKey string) Client {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.CoinGecko.APIKey == "" {
		cfg.CoinGecko.APIKey = os.Getenv("COIN_GECKO_API_KEY")
		if cfg.CoinGecko.APIKey == "" {
			log.Panic(errors.Errorf("coin gecko api key not set"))
		}

	}
	if cfg.CoinGecko.BaseUrl == "" {
		cfg.CoinGecko.BaseUrl = "https://pro-api.coingecko.com"
	}
	if len(networkMappingFromCoinGecko) == 0 {
		for k, v := range networks {
			if v.IsTestnet && cfg.TestNet {
				networkMappingFromCoinGecko[strings.ToLower(v.CoinGeckoNetworkID)] = k
				if _, hasPlatform := platformToNetworkMapping[v.CoinGeckoPlatform]; !hasPlatform {
					platformToNetworkMapping[v.CoinGeckoPlatform] = v
				}
			} else if !cfg.TestNet && !v.IsTestnet {
				networkMappingFromCoinGecko[strings.ToLower(v.CoinGeckoNetworkID)] = k
				if _, hasPlatform := platformToNetworkMapping[v.CoinGeckoPlatform]; !hasPlatform {
					platformToNetworkMapping[v.CoinGeckoPlatform] = v
				}
			}
		}
	}
	return &client{
		cfg: &cfg,
	}
}

func (c *client) ListCoins(ctx context.Context) ([]*Coin, error) {
	coinList, _, err := makeAPICall[[]coinWithPlatforms](ctx, c, "/api/v3/coins/list", map[string]any{"include_platform": true})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list all coins")
	}
	res := make(map[string][]*Coin)
	coinsToSyncMarketData := []string{}
	tokenSyncDecimals := map[string][]string{}
	platforms, err := c.getAllPlatforms(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get supported platforms")
	}
	nativeCoinsToNetwork := make(map[string][]string)
	for pl, network := range platformToNetworkMapping {
		if plat, has := platforms[pl]; !has {
			if _, hasManualMapping := platformToCoinMapping[pl]; hasManualMapping {
				nativeCoinsToNetwork[platformToCoinMapping[pl]] = append(nativeCoinsToNetwork[platformToCoinMapping[pl]], network.CoinGeckoNetworkID)
			}
		} else {
			nativeCoinsToNetwork[plat.NativeCoinId] = append(nativeCoinsToNetwork[plat.NativeCoinId], network.CoinGeckoNetworkID)
		}
	}
	for c, n := range extraCoinsToNetworkMapping {
		if _, has := nativeCoinsToNetwork[c]; !has {
			nativeCoinsToNetwork[c] = []string{n}
		}
	}
	for _, coin := range *coinList {
		networksForCoin := nativeCoinsToNetwork[coin.ID]
		if len(networksForCoin) == 0 && len(coin.Platforms) == 0 {
			continue
		}
		coinsToSyncMarketData = append(coinsToSyncMarketData, coin.ID)
		if len(coin.Platforms) > 0 {
			platformIdx := 0
			for platform, tokenAddr := range coin.Platforms {
				if network, has := platformToNetworkMapping[platform]; !has || network.SkipSyncTokens {
					continue
				}
				if platformIdx == 0 && tokenAddr != "" && !strings.Contains(tokenAddr, "/") {
					tokenSyncDecimals[platformToNetworkMapping[platform].CoinGeckoNetworkID] = append(tokenSyncDecimals[platformToNetworkMapping[platform].CoinGeckoNetworkID], tokenAddr)
				}
				network := platformToNetworkMapping[platform]
				cgNetwork := platformToNetworkMapping[platform].CoinGeckoNetworkID
				networkName := networkMappingFromCoinGecko[cgNetwork]
				if tokenAddr != "" {
					res[coin.ID] = append(res[coin.ID], &Coin{
						ID:              coin.ID,
						Symbol:          coin.Symbol,
						Name:            coin.Name,
						Network:         network.CoinGeckoNetworkID,
						ContractAddress: tokenAddr,
						Native:          slices.Contains(networksForCoin, cgNetwork),
						Decimals:        networks[networkName].DefaultDecimals,
					})
				}
				platformIdx += 1
			}
		}
		for _, cgNetwork := range networksForCoin {
			n := networkMappingFromCoinGecko[cgNetwork]
			if n == "" && c.cfg.TestNet { // Coin has no testnet
				continue
			}
			if !slices.ContainsFunc(res[coin.ID], func(c *Coin) bool {
				return c.Native && c.Network == cgNetwork
			}) {
				res[coin.ID] = append(res[coin.ID], &Coin{
					ID:              coin.ID,
					Symbol:          coin.Symbol,
					Name:            coin.Name,
					Network:         cgNetwork,
					ContractAddress: "",
					Native:          true,
					Decimals:        networks[n].DefaultDecimals,
				})
			}
		}
	}
	log.Debug(fmt.Sprintf("Initially got %v coins/tokens from coingecko, enhancing with market data...", len(res)))
	if res, err = c.enhanceWithTokenData(ctx, res, tokenSyncDecimals); err != nil {
		return nil, errors.Wrapf(err, "failed to get tokens data on initial sync")
	}
	return c.enhanceWithMarketData(ctx, res, coinsToSyncMarketData)
}

func (c *client) enhanceWithMarketData(ctx context.Context, coins map[string][]*Coin, coinIds []string) ([]*Coin, error) {
	var batches [][]string
	if len(coinIds) > maxCoinsPerPage {
		for len(coinIds) > maxCoinsPerPage {
			batches = append(batches, coinIds[:maxCoinsPerPage])
			coinIds = coinIds[maxCoinsPerPage+1:]
		}
		if len(coinIds) > 0 {
			batches = append(batches, coinIds)
		}
	} else {
		batches = append(batches, coinIds)
	}
	for i, batch := range batches {
		log.Debug(fmt.Sprintf("Fetching market data for coins %v/%v...", i+1, len(batches)))
		coinsWithPrice, err := c.GetCoins(ctx, batch)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetchh market data for coins %+v", batch)
		}
		for _, coin := range coinsWithPrice {
			updCoins := coins[coin.ID]
			for _, resCoin := range updCoins {
				resCoin.PriceUSD = coin.PriceUSD
				resCoin.IconUrl = coin.IconUrl
			}
			coins[coin.ID] = updCoins
		}
	}
	res := []*Coin{}
	for _, coin := range coins {
		res = append(res, coin...)
	}
	return res, nil
}

func (c *client) enhanceWithTokenData(ctx context.Context, coins map[string][]*Coin, tokenAddrsByNetwork map[string][]string) (map[string][]*Coin, error) {
	networkIdx := 0
	if len(tokenAddrsByNetwork) == 0 {
		return map[string][]*Coin{}, nil
	}
	for network, tokenAddrs := range tokenAddrsByNetwork {
		var batches [][]string
		if len(tokenAddrs) > MaxTokenAddrsGetTokenData {
			for len(tokenAddrs) > MaxTokenAddrsGetTokenData {
				batches = append(batches, tokenAddrs[:MaxTokenAddrsGetTokenData])
				tokenAddrs = tokenAddrs[MaxTokenAddrsGetTokenData+1:]
			}
			if len(tokenAddrs) > 0 {
				batches = append(batches, tokenAddrs)
			}
		} else {
			batches = append(batches, tokenAddrs)
		}
		for i, batch := range batches {
			log.Debug(fmt.Sprintf("Fetching data for tokens on %v (%v/%v) %v/%v...", network, networkIdx, len(tokenAddrsByNetwork), i+1, len(batches)))
			tokensData, err := c.GetTokens(ctx, network, batch)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to fetch data for tokens %v %+v", batch)
			}
			for _, coin := range tokensData {
				updCoins := coins[coin.ID]
				for _, resCoin := range updCoins {
					resCoin.Decimals = coin.Decimals
				}
				coins[coin.ID] = updCoins
			}
		}
		networkIdx += 1
	}
	return coins, nil
}

func (c *client) GetCoins(ctx context.Context, coinIDs []string) ([]*Coin, error) {
	for i, cID := range coinIDs {
		if cID == "ion" {
			coinIDs[i] = "ice"
		}
	}
	coinsData, _, err := makeAPICall[[]coin](ctx, c, "/api/v3/coins/markets",
		map[string]any{"ids": strings.Join(coinIDs, ","), "vs_currency": "USD", "per_page": maxCoinsPerPage})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get coins market data %v", strings.Join(coinIDs, ","))
	}
	res := make([]*Coin, 0, len(*coinsData))
	for _, coinData := range *coinsData {
		cgCoin := &Coin{
			ID:       coinData.ID,
			Name:     coinData.Name,
			PriceUSD: float64(coinData.CurrentPrice),
			IconUrl:  coinData.Image,
			Symbol:   coinData.Symbol,
		}
		OverwriteCoinWithStaticContent(cgCoin)
		res = append(res, cgCoin)
	}
	return res, nil
}
func (c *client) GetTokens(ctx context.Context, network string, contractAddresses []string) ([]*Coin, error) {
	tokensData, status, err := makeAPICall[page[tokenData]](ctx, c, fmt.Sprintf("/api/v3/onchain/networks/%v/tokens/multi/%v", network, strings.Join(contractAddresses, ",")), make(map[string]any))
	if err != nil {
		if status == http.StatusNotFound {
			err = ErrNotFound
		}
		return nil, errors.Wrapf(err, "failed to get tokens data on %v, %v", network, strings.Join(contractAddresses, ","))
	}
	res := make([]*Coin, 0, len(tokensData.Data))
	for _, tok := range tokensData.Data {
		var coinData *Coin
		coinData = convertTokenData(network, tok)
		OverwriteCoinWithStaticContent(coinData)
		res = append(res, coinData)
	}
	return res, nil
}
func (c *client) GetTokenPrices(ctx context.Context, network string, contractAddresses []string) ([]*Coin, error) {
	tokensData, _, err := makeAPICall[tokenPrices](ctx, c, fmt.Sprintf("/api/v3/onchain/simple/networks/%v/token_price/%v", network, strings.Join(contractAddresses, ",")), make(map[string]any))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get tokens data on %v, %v", network, strings.Join(contractAddresses, ","))
	}
	res := make([]*Coin, 0, len(tokensData.Data.Attributes.TokenPrices))
	for contractAddr, priceData := range tokensData.Data.Attributes.TokenPrices {
		var price float64
		price, err = strconv.ParseFloat(priceData, 64)
		if err != nil {
			log.Debug(fmt.Sprintf("%v", errors.Wrapf(err, "token response for %v in %v, using zero price", contractAddr, tokensData.Data.Attributes.TokenPrices)))
			price = 0
		}
		res = append(res, &Coin{
			Network:         network,
			ContractAddress: contractAddr,
			PriceUSD:        price,
		})
	}
	return res, nil
}

func (c *client) GetToken(ctx context.Context, network, tokenAddr string) (*Coin, error) {
	tok, status, err := makeAPICall[token](ctx, c, fmt.Sprintf("/api/v3/onchain/networks/%v/tokens/%v", network, tokenAddr), make(map[string]any))
	if err != nil {
		if status == http.StatusNotFound {
			err = ErrNotFound
		}
		return nil, errors.Wrapf(err, "failed to get token info for %v %v", network, tokenAddr)
	}
	return convertTokenData(network, tok.Data), nil
}

func (c *client) GetNFT(ctx context.Context, network, contractAddr string) (*NFT, error) {
	networkObj, has := networks[network]
	if !has {
		return nil, errors.Errorf("invalid network %v, cannot find plaftorm mapping", network)
	}
	nft, status, err := makeAPICall[NFT](ctx, c, fmt.Sprintf("/api/v3/nfts/%v/contract/%v", networkObj.CoinGeckoPlatform, contractAddr), make(map[string]any))
	if err != nil {
		if status == http.StatusNotFound {
			err = ErrNotFound
		}
		return nil, errors.Wrapf(err, "failed to get nft info for %v %v", network, contractAddr)
	}

	return nft, nil
}

func convertTokenData(network string, tok tokenData) *Coin {
	price, err := strconv.ParseFloat(tok.Attributes.PriceUsd, 64)
	if err != nil {
		log.Debug(fmt.Sprintf("%v", errors.Wrapf(err, "token response for %+v, using zero price", tok)))
		price = 0
	}
	return &Coin{
		ID:              tok.Attributes.CoingeckoCoinId,
		Symbol:          tok.Attributes.Symbol,
		Name:            tok.Attributes.Name,
		Network:         network,
		ContractAddress: tok.Attributes.Address,
		Decimals:        tok.Attributes.Decimals,
		PriceUSD:        price,
		IconUrl:         tok.Attributes.ImageUrl,
	}
}

func (c *client) getAllPlatforms(ctx context.Context) (map[string]*platform, error) {
	platforms, _, err := makeAPICall[[]*platform](ctx, c, "/api/v3/asset_platforms", make(map[string]any))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch supported platforms")
	}
	res := map[string]*platform{}
	for _, pl := range *platforms {
		res[pl.Id] = pl
	}
	return res, nil
}

func backoff(resp *req.Response, attempt int) stdlibtime.Duration {
	if resp != nil && resp.Response != nil && resp.StatusCode == http.StatusTooManyRequests {
		return 61 * stdlibtime.Second
	}
	switch {
	case attempt <= 1:
		return 100 * stdlibtime.Millisecond //nolint:gomnd // .
	case attempt == 2: //nolint:gomnd // .
		return 1 * stdlibtime.Second
	default:
		return 10 * stdlibtime.Second //nolint:gomnd // .
	}
}
func makeAPICall[RESP any](ctx context.Context, c *client, relativeUrl string, params map[string]any) (*RESP, int, error) {
	u, err := url.JoinPath(c.cfg.CoinGecko.BaseUrl, relativeUrl)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to build coin gecko url")
	}
	urlObj, err := url.Parse(u)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to build coin gecko url")
	}
	urlObj.RawQuery, err = form.EncodeToString(params)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to build coin gecko url")
	}
	uri := urlObj.String()
	header := "x-cg-pro-api-key"
	if resp, err := req.
		SetContext(ctx).
		SetRetryCount(3). //nolint:gomnd // .
		SetRetryInterval(backoff).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to call coin gecko %v", uri))
			} else {
				body, bErr := resp.ToString()
				log.Error(errors.Wrapf(bErr, "failed to parse negative response body for coin gecko call to %v", uri))
				log.Error(errors.Errorf("failed to call coin gecko api %v with status code:%v, body:%v, retrying... ", uri, resp.GetStatusCode(), body))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || (resp.GetStatusCode() != http.StatusOK && resp.GetStatusCode() != http.StatusNotFound)
		}).
		SetHeader(header, c.cfg.CoinGecko.APIKey).
		SetHeader("Accept", "application/json").
		Get(uri); err != nil {
		return nil, 0, errors.Wrapf(err, "failed to call coin gecko api %v", uri)
	} else if statusCode := resp.GetStatusCode(); statusCode != http.StatusOK && statusCode != http.StatusBadRequest {
		return nil, statusCode, errors.Errorf("[%v]failed to call coin gecko api %v", statusCode, uri)
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, statusCode, errors.Wrapf(err2, "failed to read body of coin gecko api call %v", uri)
	} else { //nolint:revive // .
		var response RESP
		if jerr := json.UnmarshalContext(ctx, data, &response); jerr != nil {
			return nil, statusCode, errors.Wrapf(jerr, "failed to unmarshal json on coin gecko api call %v %v", uri, string(data))
		}
		return &response, statusCode, nil
	}
}

func (c *Coin) SymbolGroup() string {
	if c.ID == "" {
		return c.ContractAddress
	}

	return c.ID
}
func MapNetwork(network string) (string, error) {
	if coingeckoNetwork, hasNetwork := networks[network]; !hasNetwork || coingeckoNetwork == nil {
		return "", ErrInvalidNetwork
	} else {
		return coingeckoNetwork.CoinGeckoNetworkID, nil
	}
}
func MapNetworkFromCoinGecko(network string) (*Network, error) {
	if mappedNetwork, hasNetwork := networkMappingFromCoinGecko[strings.ToLower(network)]; !hasNetwork || mappedNetwork == "" {
		return nil, ErrInvalidNetwork
	} else {
		return networks[mappedNetwork], nil
	}
}

func IsTestnet(network string) bool {
	return networks[network].IsTestnet
}

func (n *NFT) ImageUri() string {
	if n.Image.Thumb != "" {
		return n.Image.Thumb
	}
	if n.Image.Small2X != "" {
		return n.Image.Small2X
	}
	return n.Image.Small
}

func OverwriteCoinWithStaticContent(c *Coin) {
	if overwrite, hasOverwrite := coinOverwrites["id:"+strings.ToLower(c.ID)]; hasOverwrite {
		if overwrite.Name != "" {
			c.Name = overwrite.Name
		}
		if overwrite.IconUrl != "" {
			c.IconUrl = overwrite.IconUrl
		}
	} else if overwrite, hasOverwrite = coinOverwrites["symbol:"+strings.ToLower(c.Symbol)]; hasOverwrite {
		if overwrite.Name != "" {
			c.Name = overwrite.Name
		}
		if overwrite.Symbol != "" {
			c.Symbol = overwrite.Symbol
		}
		if overwrite.Decimals != 0 {
			c.Decimals = overwrite.Decimals
		}
		if overwrite.IconUrl != "" {
			c.IconUrl = overwrite.IconUrl
		}
	}
}

func (c *client) GetAllNetworks() []*Network {
	filteredNetworks := []*Network{}
	for _, n := range networks {
		if c.cfg.TestNet == n.IsTestnet {
			filteredNetworks = append(filteredNetworks, n)
		}
	}
	return filteredNetworks
}
