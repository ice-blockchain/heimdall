// SPDX-License-Identifier: ice License 1.0

package coingecko

import (
	"context"

	"github.com/pkg/errors"
)

type (
	Client interface {
		ListCoins(ctx context.Context) ([]*Coin, error)
		GetToken(ctx context.Context, network, tokenAddr string) (*Coin, error)
		GetTokens(ctx context.Context, network string, tokenAddr []string) ([]*Coin, error)
		GetTokenPrices(ctx context.Context, network string, contractAddresses []string) ([]*Coin, error)
		GetCoins(ctx context.Context, coinIDs []string) ([]*Coin, error)
		GetNFT(ctx context.Context, network string, contractAddress string) (*NFT, error)
		GetAllNetworks() []*Network
	}
	NetworkName     = string
	ContractAddress = string
	Coin            struct {
		ID              string
		Symbol          string
		Name            string
		Network         NetworkName
		ContractAddress ContractAddress
		Decimals        int
		PriceUSD        float64
		Native          bool
		IconUrl         string
	}
	NFT struct {
		Id              string `json:"id"`
		ContractAddress string `json:"contract_address"`
		Name            string `json:"name"`
		Symbol          string `json:"symbol"`
		Description     string `json:"description"`
		Image           struct {
			Thumb   string `json:"thumb"`
			Small2X string `json:"small_2x"`
			Small   string `json:"small"`
		} `json:"image"`
	}
	Network struct {
		ID                 string   `json:"id"`
		CoinGeckoNetworkID string   `json:"-"`
		CoinGeckoPlatform  string   `json:"-"`
		DisplayName        string   `json:"displayName"`
		IsTestnet          bool     `json:"isTestnet"`
		Image              string   `json:"image"`
		ExplorerURL        string   `json:"explorerUrl"`
		DefaultDecimals    int      `json:"-"`
		SkipSyncTokens     bool     `json:"-"`
		Tier               uint8    `json:"tier"`
		PrioritizedCoins   []string `json:"-"`
	}
)

var (
	ErrNotFound       = errors.New("not found")
	ErrInvalidNetwork = errors.New("invalid network")

	networkMappingFromCoinGecko map[string]string = map[string]string{}
	platformToNetworkMapping                      = map[string]*Network{}

	platformToCoinMapping = map[string]string{
		"bitcoin":       "bitcoin",
		"berachain":     "berachain-bera",
		"plume-network": "plume",
	}
	extraCoinsToNetworkMapping = map[string]string{
		"litecoin": "litecoin",
		"dogecoin": "dogecoin",
		"plume":    "plume",
	}
)

type (
	client struct {
		cfg                  *config
		nativeCoinsToNetwork map[string][]string
	}
	config struct {
		TestNet   bool `yaml:"testnet" mapstructure:"testnet"`
		CoinGecko struct {
			APIKey  string `yaml:"api-key" mapstructure:"api-key"`
			BaseUrl string `yaml:"base-url" mapstructure:"base-url"`
		} `yaml:"coin-gecko" mapstructure:"coin-gecko"`
	}
	coinWithPlatforms struct {
		ID        string                          `json:"id"`
		Symbol    string                          `json:"symbol"`
		Name      string                          `json:"name"`
		Platforms map[NetworkName]ContractAddress `json:"platforms"`
	}
	coin struct {
		ID           string  `json:"id"`
		Symbol       string  `json:"symbol"`
		Name         string  `json:"name"`
		Image        string  `json:"image"`
		CurrentPrice float64 `json:"current_price"`
	}
	token struct {
		Data tokenData `json:"data"`
	}
	tokenData struct {
		Id         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Address         string `json:"address"`
			Name            string `json:"name"`
			Symbol          string `json:"symbol"`
			ImageUrl        string `json:"image_url"`
			CoingeckoCoinId string `json:"coingecko_coin_id"`
			Decimals        int    `json:"decimals"`
			PriceUsd        string `json:"price_usd"`
		} `json:"attributes"`
	}
	page[T any] struct {
		Data []T `json:"data"`
	}
	tokenPrices struct {
		Data struct {
			Id         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				TokenPrices map[string]string `json:"token_prices"`
			} `json:"attributes"`
		} `json:"data"`
	}
	platform struct {
		Id           string `json:"id"`
		NativeCoinId string `json:"native_coin_id"`
	}
	platformNetwork struct {
		Network    string
		SkipTokens bool
	}
)

const (
	maxCoinsPerPage             = 250
	MaxTokenAddrsGetTokenData   = 30
	MaxTokenAddrsGetTokenPrices = 100
)
