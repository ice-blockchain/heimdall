// SPDX-License-Identifier: ice License 1.0

package coingecko

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
		log.Panic(errors.Errorf("coin gecko api key not set"))
	}
	return &client{
		cfg: &cfg,
	}
}

func init() {
	networkToPlatformMapping = make(map[string]string)
	for k, v := range platformToNetworkMapping {
		networkToPlatformMapping[v] = k
	}
}

func (c *client) ListCoins(ctx context.Context) ([]*Coin, error) {
	coinList, _, err := makeAPICall[[]coinWithPlatforms](ctx, c, "/api/v3/coins/list", map[string]any{"include_platform": true})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list all coins")
	}
	res := make([]*Coin, 0, len(*coinList))
	for _, coin := range *coinList {
		if len(coin.Platforms) == 0 {
			res = append(res, &Coin{
				ID:              coin.ID,
				Symbol:          coin.Symbol,
				Name:            coin.Name,
				Network:         "",
				ContractAddress: "",
			})
			continue
		}
		for platform, tokenAddr := range coin.Platforms {
			if _, has := platformToNetworkMapping[platform]; !has {
				continue
			}
			res = append(res, &Coin{
				ID:              coin.ID,
				Symbol:          coin.Symbol,
				Name:            coin.Name,
				Network:         platformToNetworkMapping[platform],
				ContractAddress: tokenAddr,
			})
		}
	}
	return res, nil
}

func (c *client) GetCoins(ctx context.Context, coinIDs []string) ([]*Coin, error) {
	coinsData, _, err := makeAPICall[[]coin](ctx, c, "/api/v3/coins/markets",
		map[string]any{"ids": strings.Join(coinIDs, ","), "vs_currency": "USD"})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get coins market data %v", strings.Join(coinIDs, ","))
	}
	res := make([]*Coin, 0, len(*coinsData))
	for _, coinData := range *coinsData {
		res = append(res, &Coin{
			ID:       coinData.ID,
			Name:     coinData.Name,
			PriceUSD: float64(coinData.CurrentPrice),
			IconUrl:  coinData.Image,
		})
	}
	return res, nil
}
func (c *client) GetTokens(ctx context.Context, network string, contractAddresses []string) ([]*Coin, error) {
	tokensData, _, err := makeAPICall[page[tokenData]](ctx, c, fmt.Sprintf("/api/v3/onchain/networks/%v/tokens/multi/%v", network, strings.Join(contractAddresses, ",")), make(map[string]any))
	if err != nil {

		return nil, errors.Wrapf(err, "failed to get tokens data on %v, %v", network, strings.Join(contractAddresses, ","))
	}
	res := make([]*Coin, 0, len(tokensData.Data))
	for _, tok := range tokensData.Data {
		var coinData *Coin
		coinData, err = convertTokenData(network, tok)
		if err != nil {
			continue
			//return nil, errors.Wrapf(err, "failed to parse multi token response for %+v", tok)
		}
		res = append(res, coinData)
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
	return convertTokenData(network, tok.Data)
}

func (c *client) GetNFT(ctx context.Context, network, contractAddr string) (*NFT, error) {
	platform, has := networkToPlatformMapping[strings.ToLower(network)]
	if !has {
		return nil, errors.Errorf("invalid network %v, cannot find plaftorm mapping", network)
	}
	nft, status, err := makeAPICall[NFT](ctx, c, fmt.Sprintf("/api/v3/nfts/%v/contract/%v", platform, contractAddr), make(map[string]any))
	if err != nil {
		if status == http.StatusNotFound {
			err = ErrNotFound
		}
		return nil, errors.Wrapf(err, "failed to get token info for %v %v", network, contractAddr)
	}
	return nft, nil
}

func convertTokenData(network string, tok tokenData) (*Coin, error) {
	price, err := strconv.ParseFloat(tok.Attributes.PriceUsd, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "failred to parse priceUsd: %v", tok.Attributes.PriceUsd)
	}
	return &Coin{
		ID:              tok.Attributes.CoingeckoCoinId, // Data.ID?
		Symbol:          tok.Attributes.Symbol,
		Name:            tok.Attributes.Name,
		Network:         network,
		ContractAddress: tok.Attributes.Address,
		Decimals:        tok.Attributes.Decimals,
		PriceUSD:        price,
		IconUrl:         tok.Attributes.ImageUrl,
	}, nil
}

func backoff(_ *req.Response, attempt int) stdlibtime.Duration {
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
	if !strings.Contains(c.cfg.CoinGecko.BaseUrl, "pro") {
		header = "x-cg-demo-api-key"
	}
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

func (c *Coin) MappedNetwork() string {
	return c.Network
}
func (c *Coin) SymbolGroup() string {
	if c.ID == "" {
		return c.ContractAddress
	}

	return c.ID
}
func MapNetwork(network string) (string, error) {

	if coingeckoNetwork, hasNetwork := networksMapping[strings.ToLower(network)]; !hasNetwork || coingeckoNetwork == "" {
		return "", ErrInvalidNetwork
	} else {
		return coingeckoNetwork, nil
	}

}
