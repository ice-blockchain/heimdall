// SPDX-License-Identifier: ice License 1.0

package coins

import (
	"context"
	_ "embed"
	"io"
	"sync"
	stdlibtime "time"

	"github.com/pkg/errors"
	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/coins/internal/coingecko"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

type (
	Network = string
	Coins   interface {
		io.Closer
		HealthCheck(ctx context.Context) error
		Import(ctx context.Context, network, contractAddress string) (*Coin, error)
		GetAllCoins(ctx context.Context) (uint64, []*SymbolGroupWithCoins, error)
		GetVersionedCoins(ctx context.Context, userID string, knownVersion *int) (latestVersion uint64, coinDiff []*Coin, err error)
		SyncCoins(ctx context.Context, symbolGroups []string) ([]*Coin, error)
		GetCoinsOfSymbolGroup(ctx context.Context, symbolGroups []string) ([]*Coin, error)
		GetFees(network string) *Fee
		ImportNFTs(ctx context.Context, network string, NFTs []WalletNFT) ([]*NFT, error)
	}
	Sync interface {
		io.Closer
		HealthCheck(ctx context.Context) error
	}
	NftID struct {
		ContractAddress string
		Network         string
	}
	Coin struct {
		ID              string              `json:"id"`
		Name            string              `json:"name"`
		Symbol          string              `json:"symbol"`
		SymbolGroup     string              `json:"symbolGroup"`
		Network         string              `json:"network"`
		ContractAddress string              `json:"contractAddress"`
		IconURL         string              `json:"iconURL"`
		PriceUSD        float64             `json:"priceUSD"`
		Decimals        uint8               `json:"decimals"`
		Version         *uint64             `json:"version,omitempty"`
		SyncFrequency   stdlibtime.Duration `json:"syncFrequency"`
	}
	WalletNFT map[string]any
	NFT       struct {
		WalletNFT
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	SymbolGroupWithCoins struct {
		SymbolGroup string  `json:"symbol_group"`
		Coins       []*Coin `json:"coins"`
	}
)

const (
	DefaultWalletViewCoinSymbolGroup = "ice"
)

var (
	ErrNotFound   = storage.ErrNotFound
	ErrNotChanged = errors.New("not changed")
)

const (
	applicationYamlKey         = "coins"
	initialVersion             = 0
	coinSyncIterationDuration  = 1 * stdlibtime.Minute
	coinSyncIterationBatchSize = 100
	targetCoinGeckoCallsPerMin = 100
)

var (
	//go:embed DDL.sql
	ddl string
)

type (
	coinsRepository struct {
		db                 *storage.DB
		shutdown           func() error
		cfg                *config
		coinGeckoClient    coingecko.Client
		nftCoinGeckoClient coingecko.Client
	}
	coinSync struct {
		db              *storage.DB
		shutdown        func() error
		cancel          context.CancelFunc
		wg              sync.WaitGroup
		cfg             *config
		coinGeckoClient coingecko.Client
		metrics         metrics.Registry
	}
	config struct {
		Fees                    map[Network]Fee                `yaml:"fees" mapstructure:"fees"`
		SyncFrequency           map[string]stdlibtime.Duration `yaml:"syncFrequency" mapstructure:"syncFrequency"`
		DefaultSyncFrequency    stdlibtime.Duration            `yaml:"defaultSyncFrequency" mapstructure:"defaultSyncFrequency"`
		SyncTokensDataFrequency stdlibtime.Duration            `yaml:"syncTokensDataFrequency" mapstructure:"syncTokensDataFrequency"`
	}
	Fee struct {
		Slow     *FeeWithDuration `json:"slow" yaml:"slow"`
		Standard *FeeWithDuration `json:"standard" yaml:"standard"`
		Fast     *FeeWithDuration `json:"fast" yaml:"fast"`
	}
	FeeWithDuration struct {
		MaxPriorityFee int `json:"maxPriorityFee" yaml:"maxPriorityFee"`
		MaxFee         int `json:"maxFee" yaml:"maxFee"`
		WaitTime       int `json:"waitTime" yaml:"waitTime"`
	}
	coin struct {
		SyncFrequency   stdlibtime.Duration
		CreatedAt       *time.Time
		UpdatedAt       *time.Time
		DataUpdatedAt   *time.Time
		Decimals        uint8
		Version         uint64
		PriceUSD        float64
		ID              string
		CoinGeckoCoinID string `db:"coingecko_coin_id"`
		Network         string
		Name            string
		ContractAddress string
		Symbol          string
		SymbolGroup     string
		IconUrl         string
	}
	coinToSync struct {
		Network           string
		ContractAddresses []string `db:"contract_addresses"`
		CoinGeckoCoinIDs  []string `db:"coin_ids"`
		SyncTokenFullData bool     `db:"sync_token_full_data"`
	}
	nft struct {
		Network         string
		TokenID         string
		Name            string
		Description     string
		TokenStandard   string
		ContractAddress string
		Symbol          string
		IconUrl         string
	}
)
