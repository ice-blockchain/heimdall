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
		FloorPrice struct {
			NativeCurrency float64 `json:"native_currency"`
			Usd            float64 `json:"usd"`
		} `json:"floor_price"`
		Ath struct {
			NativeCurrency float64 `json:"native_currency"`
			Usd            float64 `json:"usd"`
		} `json:"ath"`
	}
)

var (
	ErrNotFound       = errors.Errorf("not found")
	ErrInvalidNetwork = errors.Errorf("invalid network")
	networksMapping   = map[string]string{
		"algorand":          "algorand",
		"algorandtestnet":   "algorand",
		"arbitrumone":       "arbitrum",
		"arbitrumsepolia":   "arbitrum",
		"avalanchec":        "avax",
		"avalanchecfuji":    "avax",
		"base":              "base",
		"basesepolia":       "base",
		"bitcoin":           "bitcoin-cash",
		"bitcointestnet3":   "bitcoin-cash",
		"bsc":               "bsc",
		"bsctestnet":        "bsc",
		"cardano":           "cardano",
		"cardanopreprod":    "cardano",
		"ethereum":          "eth",
		"ethereumsepolia":   "eth",
		"fantomopera":       "ftm",
		"fantomtestnet":     "ftm",
		"icp (aka dfinity)": "internet-computer",
		"kaspa":             "kaspa",
		"kusama":            "kusama",
		"westend":           "polkadot",
		"ogy":               "",
		"litecoin":          "",
		"optimism":          "optimism",
		"optimismsepolia":   "optimism",
		"polkadot":          "polkadot",
		"seipacific1":       "sei-network",
		"seiatlantic2":      "sei-network",
		"stellar":           "stellar",
		"stellartestnet":    "stellar",
		"tezos":             "tezos",
		"tezosghostnet":     "tezos",
		"solana":            "solana",
		"solanadevnet":      "solana",
		"polygon":           "polygon_pos",
		"polygonamoy":       "polygon_pos",
		"ton":               "ton",
		"tontestnet":        "ton",
		"tronnile":          "tron",
		"tron":              "tron",
		"xrpledger":         "xrp",
		"xrpledgertestnet":  "xrp",
	}
	platformToNetworkMapping = map[string]string{
		"ethereum":            "eth",
		"base":                "base",
		"bitcoin-cash":        "bitcoin-cash",
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
		"tron":                "tron",
		"cardano":             "cardano",
		"polkadot":            "polkadot",
		"sei-network":         "sei-network",
		"stellar":             "stellar",
		"tezos":               "tezos",
		"kasplex":             "kaspa",
		"internet-computer":   "internet-computer",
	}
	networkToPlatformMapping map[string]string
)

type (
	client struct {
		cfg *config
	}
	config struct {
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
			Address           string `json:"address"`
			Name              string `json:"name"`
			Symbol            string `json:"symbol"`
			ImageUrl          string `json:"image_url"`
			CoingeckoCoinId   string `json:"coingecko_coin_id"`
			Decimals          int    `json:"decimals"`
			TotalSupply       string `json:"total_supply"`
			PriceUsd          string `json:"price_usd"`
			FdvUsd            string `json:"fdv_usd"`
			TotalReserveInUsd string `json:"total_reserve_in_usd"`
			VolumeUsd         struct {
				H24 string `json:"h24"`
			} `json:"volume_usd"`
			MarketCapUsd string `json:"market_cap_usd"`
		} `json:"attributes"`
		Relationships struct {
			TopPools struct {
				Data []struct {
					Id   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"top_pools"`
		} `json:"relationships"`
	}
	page[T any] struct {
		Data []T `json:"data"`
	}
)
