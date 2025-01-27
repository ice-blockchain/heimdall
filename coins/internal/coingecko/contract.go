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
	}
	Network         = string
	ContractAddress = string
	Coin            struct {
		ID              string
		Symbol          string
		Name            string
		Network         Network
		ContractAddress ContractAddress
		Decimals        int
		PriceUSD        float64
		IconUrl         string
	}
	NFT struct {
		Id              string `json:"id"`
		ContractAddress string `json:"contract_address"`
		Name            string `json:"name"`
		Symbol          string `json:"symbol"`
		Description     string `json:"description"`
		Image           struct {
			Thumb string `json:"thumb"`
		} `json:"image"`
	}
)

var (
	ErrNotFound       = errors.New("not found")
	ErrInvalidNetwork = errors.New("invalid network")
	networksMapping   = map[string]string{
		"algorand":          "algorand",
		"algorandtestnet":   "algorand",
		"arbitrumone":       "arbitrum",
		"arbitrumsepolia":   "arbitrum",
		"avalanchec":        "avax",
		"avalanchecfuji":    "avax",
		"base":              "base",
		"basesepolia":       "base",
		"bitcoin":           "bitcoin",
		"bitcointestnet3":   "bitcoin",
		"bsc":               "bsc",
		"bsctestnet":        "bsc",
		"cardano":           "cardano",
		"cardanopreprod":    "cardano",
		"ethereum":          "eth",
		"ethereumsepolia":   "eth",
		"fantomopera":       "ftm",
		"fantomtestnet":     "ftm",
		"icp (aka dfinity)": "icp",
		"kusama":            "kusama",
		"optimism":          "optimism",
		"optimismsepolia":   "optimism",
		"seipacific1":       "sei-network",
		"seiatlantic2":      "sei-network",
		"solana":            "solana",
		"solanadevnet":      "solana",
		"polygon":           "polygon_pos",
		"polygonamoy":       "polygon_pos",
		"ton":               "ton",
		"tontestnet":        "ton",
		"ion":               "ion",
		"iontestnet":        "ion",
		"tronnile":          "tron",
		"tron":              "tron",
		"xrpledger":         "xrp",
		"xrpledgertestnet":  "xrp",
		// Those networks below are not presented on /api/v3/onchain/networks on coingecko
		// We cannot req tokens on them, it responds 404
		//"ogy":               "",
		//"litecoin":          "",
		//"tezos":             "tezos",
		//"tezosghostnet":     "tezos",
		//"stellartestnet":    "stellar",
		//"stellar":   	       "stellar",
		//"kaspa":             "kaspa",
		//"polkadot":          "polkadot",
		//"westend":           "polkadot",
	}
	reversedNetworkMapping map[string]string = map[string]string{}
	testnetNetworks                          = []string{
		"algorandtestnet",
		"arbitrumsepolia",
		"avalanchecfuji",
		"basesepolia",
		"bitcointestnet3",
		"bsctestnet",
		"cardanopreprod",
		"ethereumsepolia",
		"fantomtestnet",
		"optimismsepolia",
		"seiatlantic2",
		"solanadevnet",
		"polygonamoy",
		"tontestnet",
		"iontestnet",
		"tronnile",
		"xrpledgertestnet",
		// Those networks below are not presented on /api/v3/onchain/networks on coingecko
		// We cannot req tokens on them, it responds 404
		//"ogy":               "",
		//"litecoin":          "",
		//"tezosghostnet":     "tezos",
		//"stellartestnet":    "stellar",
		//"westend":           "polkadot",
	}
	platformToNetworkMapping = map[string]string{
		"ethereum":            "eth",
		"base":                "base",
		"bitcoin":             "bitcoin",
		"binance-smart-chain": "bsc",
		"polygon-pos":         "polygon_pos",
		"avalanche":           "avax",
		"fantom":              "ftm",
		"arbitrum-one":        "arbitrum",
		"optimistic-ethereum": "optimism",
		"solana":              "solana",
		"kava":                "kava",
		"kusama":              "kusama",
		"the-open-network":    "ton",
		// "ice-open-network":    "ion", // We need platform/network listing on coin gecko
		"tron":              "tron",
		"cardano":           "cardano",
		"sei-network":       "sei-network",
		"internet-computer": "icp",
		// Those networks below are not presented on /api/v3/onchain/networks on coingecko
		// We cannot req tokens on them, it responds 404
		//"tezos": "tezos",
		//"kasplex":             "kaspa",
		//"polkadot":            "polkadot",
	}
	networkToPlatformMapping  map[string]string
	platformToDecimalsMapping = map[string]int{
		"ethereum":            18,
		"base":                18,
		"bitcoin":             8,
		"binance-smart-chain": 18,
		"polygon-pos":         18,
		"avalanche":           18,
		"fantom":              18,
		"arbitrum-one":        18,
		"optimistic-ethereum": 18,
		"solana":              9,
		"kava":                6,
		"kusama":              12,
		"the-open-network":    9,
		"ice-open-network":    9,
		"tron":                18,
		"cardano":             18,
		"sei-network":         18,
		"internet-computer":   18,
		// Those networks below are not presented on /api/v3/onchain/networks on coingecko
		// We cannot req tokens on them, it responds 404
		//"tezos":               6,
		//"kasplex":             8,
		//"polkadot":            16,
	}

	platformToCoinMapping = map[string]string{
		"bitcoin": "bitcoin",
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
		ID        string                      `json:"id"`
		Symbol    string                      `json:"symbol"`
		Name      string                      `json:"name"`
		Platforms map[Network]ContractAddress `json:"platforms"`
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
)

const (
	maxCoinsPerPage             = 250
	MaxTokenAddrsGetTokenData   = 30
	MaxTokenAddrsGetTokenPrices = 100
)
