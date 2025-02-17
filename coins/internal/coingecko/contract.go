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
		"Algorand":         "algorand",
		"AlgorandTestnet":  "algorand",
		"ArbitrumOne":      "arbitrum",
		"ArbitrumSepolia":  "arbitrum",
		"AptosTestnet":     "aptos",
		"Aptos":            "aptos",
		"AvalancheC":       "avax",
		"AvalancheCFuji":   "avax",
		"Base":             "base",
		"BaseSepolia":      "base",
		"Bitcoin":          "bitcoin",
		"BitcoinTestnet3":  "bitcoin",
		"Bsc":              "bsc",
		"BscTestnet":       "bsc",
		"Cardano":          "cardano",
		"CardanoPreprod":   "cardano",
		"Dogecoin":         "dogecoin",
		"Ethereum":         "eth",
		"EthereumSepolia":  "eth",
		"FantomOpera":      "ftm",
		"FantomTestnet":    "ftm",
		"ICP":              "icp",
		"Kusama":           "kusama",
		"Optimism":         "optimism",
		"OptimismSepolia":  "optimism",
		"SeiPacific1":      "sei-network",
		"SeiAtlantic2":     "sei-network",
		"Solana":           "solana",
		"SolanaDevnet":     "solana",
		"Polygon":          "polygon_pos",
		"PolygonAmoy":      "polygon_pos",
		"Ton":              "ton",
		"TonTestnet":       "ton",
		"Ion":              "ion",
		"IonTestnet":       "ion",
		"TronNile":         "tron",
		"Tron":             "tron",
		"XrpLedger":        "xrp",
		"XrpLedgerTestnet": "xrp",
		"Litecoin":         "litecoin",
		"Tezos":            "tezos",
		"TezosGhostnet":    "tezos",
		"StellarTestnet":   "stellar",
		"Stellar":          "stellar",
		"Kaspa":            "kaspa",
		"Polkadot":         "polkadot",
		"Westend":          "polkadot",
	}
	reversedNetworkMapping map[string]string = map[string]string{}
	testnetNetworks                          = []string{
		"algorandtestnet",
		"arbitrumsepolia",
		"aptostestnet",
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
		"tezosghostnet",
		"stellartestnet",
		"westend",
	}
	platformToNetworkMapping = map[string]platformNetwork{
		"aptos":               platformNetwork{"aptos", false},
		"ethereum":            platformNetwork{"eth", false},
		"base":                platformNetwork{"base", false},
		"bitcoin":             platformNetwork{"bitcoin", false},
		"binance-smart-chain": platformNetwork{"bsc", false},
		"polygon-pos":         platformNetwork{"polygon_pos", false},
		"avalanche":           platformNetwork{"avax", false},
		"fantom":              platformNetwork{"ftm", false},
		"arbitrum-one":        platformNetwork{"arbitrum", false},
		"optimistic-ethereum": platformNetwork{"optimism", false},
		"solana":              platformNetwork{"solana", false},
		"kava":                platformNetwork{"kava", false},
		"kusama":              platformNetwork{"kusama", false},
		"the-open-network":    platformNetwork{"ton", false},
		// "ice-open-network":    "ion", // We need platform/network listing on coin gecko
		"tron":              platformNetwork{"tron", false},
		"cardano":           platformNetwork{"cardano", false},
		"sei-network":       platformNetwork{"sei-network", false},
		"internet-computer": platformNetwork{"icp", false},
		// Those networks below are not presented on /api/v3/onchain/networks on coingecko,
		// so we skip tokens for them, only native coins
		"tezos":    platformNetwork{"tezos", true},
		"kasplex":  platformNetwork{"kaspa", true},
		"polkadot": platformNetwork{"polkadot", true},
		"stellar":  platformNetwork{"stellar", true},
		"xrp":      platformNetwork{"xrp", true},
		"litecoin": platformNetwork{"litecoin", true},
		"algorand": platformNetwork{"algorand", true},
	}
	networkToPlatformMapping  map[string]string
	platformToDecimalsMapping = map[string]int{
		"ethereum":            18,
		"base":                18,
		"bitcoin":             8,
		"binance-smart-chain": 18,
		"polygon-pos":         18,
		"avalanche":           18,
		"dogecoin":            8,
		"litecoin":            8,
		"algorand":            6,
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
		"xrp":                 6,
		"tezos":               6,
		"kasplex":             8,
		"polkadot":            16,
	}

	platformToCoinMapping = map[string]string{
		"bitcoin": "bitcoin",
	}
	extraCoinsToNetworkMapping = map[string]string{
		"litecoin": "litecoin",
		"dogecoin": "dogecoin",
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
