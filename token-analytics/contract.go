// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	stdlibtime "time"

	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/quicknode"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/time"
)

type (
	UserRepository interface {
		Close() error
		HealthCheck(ctx context.Context) error
		UpsertUser(ctx context.Context, id, masterPubkey, blockchainAddress, username, displayName, avatar string, verified bool, ionConnectRelays []string) error
		SetVerified(ctx context.Context, masterPubkey string) error
		UpdateBlockchainAddress(ctx context.Context, masterPubkey, blockchainAddress string) error
	}

	TokenAnalytics interface {
		Close() error
		HealthCheck(ctx context.Context) error
		UserRepository
		MustStart(ctx context.Context)
		GetCommunityTokensByIonConnectAddresses(ctx context.Context, ionConnectAddresses []string, requestorMasterPubkey string) ([]*CommunityToken, error)
		GetCommunityTokensByType(ctx context.Context, tokenType, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		GetLatestTrades(ctx context.Context, ionConnectAddress string, limit, offset uint64, startFrom *stdlibtime.Time) (trades []*Trade, maxTs stdlibtime.Time, err error)
		GetOHLVCHistory(ctx context.Context, now, startPoint stdlibtime.Time, ionContentAddress string, interval Interval) (res []*OHLCV, err error)
		GetOHLVCRecent(ctx context.Context, now stdlibtime.Time, ionContentAddress string, interval Interval) (*OHLCV, error)
		GetTradingStats(ctx context.Context, now stdlibtime.Time, ionContentAddress string) (*TradeStats, error)
		UpdateTradingStats(ctx context.Context, now stdlibtime.Time, ionConnectAddress string) (*TradeStats, error)
		CreateViewingSession(ctx context.Context, sessionType, clientIP, deviceKey string) (sessionID string, ttl uint64, err error)
		GetTopHolders(ctx context.Context, ionConnectAddress string, limit int64) ([]*TopHolderPosition, error)
		GetTokensFromViewingSession(ctx context.Context, sessionType, sessionID, keyword string, limit, offset uint64) ([]*CommunityToken, error)
	}

	SavePoint struct {
		TransactionIndex uint64 `db:"transaction_index"`
		BlockNumber      uint64 `db:"block_number"`
	}

	ViewingSession struct {
		ID        string `redis:"id"`
		Type      string `redis:"type"`
		UserIP    string `redis:"user_ip"`
		CreatedAt int64  `redis:"created_at"`
		TTL       int64  `redis:"ttl"`
	}
	TradeType string
	JSON      map[string]any

	Interval   string
	WindowSize stdlibtime.Duration
)

const (
	TokenTypeProfile = "profile"
	TokenTypePost    = "post"
	TokenTypeArticle = "article"
	TokenTypeVideo   = "video"

	TokenTypeLatest   = "latest"
	TokenTypeFeatured = "featured"
	TokenTypeTop      = "top"
	TokenTypeTrending = "trending"
)

var (
	//go:embed DDL.sql
	sourceDDL      string
	validIntervals = map[Interval]WindowSize{
		Interval("1m"):  WindowSize(1 * stdlibtime.Hour),
		Interval("2m"):  WindowSize(1 * stdlibtime.Hour),
		Interval("3m"):  WindowSize(1 * stdlibtime.Hour),
		Interval("5m"):  WindowSize(12 * stdlibtime.Hour),
		Interval("10m"): WindowSize(12 * stdlibtime.Hour),
		Interval("15m"): WindowSize(12 * stdlibtime.Hour),
		Interval("30m"): WindowSize(24 * stdlibtime.Hour),
		Interval("45m"): WindowSize(24 * stdlibtime.Hour),
		Interval("1h"):  WindowSize(24 * stdlibtime.Hour),
		Interval("2h"):  WindowSize(48 * stdlibtime.Hour),
		Interval("3h"):  WindowSize(48 * stdlibtime.Hour),
		Interval("4h"):  WindowSize(48 * stdlibtime.Hour),
		Interval("24h"): WindowSize(30 * 24 * stdlibtime.Hour),
	}
)

const (
	applicationYamlKey = "token-analytics"
	tradeTypeBuy       = TradeType("buy")
	tradeTypeSell      = TradeType("sell")

	volumeUpdateInterval                     = 1 * stdlibtime.Minute
	volume24hMaterializedViewRefreshInterval = 30 * stdlibtime.Second

	globalTopSetKey         = "token_analytics:global:top"
	globalTrendingSetKey    = "token_analytics:global:trending"
	userSessionKeyPrefix    = "token_analytics:session:%s:%s"  // {type}:{sessionID}
	userIdentifierMapPrefix = "token_analytics:user_map:%s:%s" // {type}:{IP:DeviceKey} -> sessionID

	sessionTypeTop      = "top"
	sessionTypeTrending = "trending"

	defaultViewingSessionTTL = 30 * stdlibtime.Minute
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

type (
	config struct {
		Workers         uint   `yaml:"workers"`
		BatchSize       uint   `yaml:"batchSize"`
		IONTokenAddress string `yaml:"ionTokenAddress"`
		BondingCurve    struct {
			SmartContractAddress string `yaml:"smartContractAddress"`
		} `yaml:"bondingCurve" mapstructure:"bondingCurve"`
	}
	tokenAnalytics struct {
		bondingCurveContractAddress string
		ingestedDataDB              *storage.DB
		processedDataDB             storagev3.DB
		questDB                     *questdb.DB
		shutdown                    func() error
		cfg                         *config
		wg                          *sync.WaitGroup
		quickNode                   quicknode.Client
		metrics                     metrics.Registry
		ionPriceUSD                 *atomic.Pointer[float64]
		// TODO: xmap for latest creator token prices to calc content token price
	}
	txEvent struct {
		TransactionIndex uint64      `db:"transaction_index"`
		BlockNumber      uint64      `db:"block_number"`
		TransactionHash  string      `db:"transaction_hash"`
		FromAddress      string      `db:"from_address"`
		ToAddress        string      `db:"to_address"`
		BlockTimestamp   *time.Time  `db:"block_timestamp"`
		ChainID          string      `db:"chain_id"`
		Value            string      `db:"value"`
		Input            string      `db:"input"`
		Logs             txEventLogs `db:"logs"`
	}

	txEventLogs   []JSON
	savePointData struct {
		WorkerIdx        uint   `redis:"-"`
		BlockNumber      uint64 `redis:"block_number"`
		TransactionIndex uint64 `redis:"transaction_index"`
		UpdatedAt        int64  `redis:"updated_at"`
	}

	ionPricingStats struct {
		CirculatingSupply     float64 `json:"circulatingSupply"`
		TotalSupply           float64 `json:"totalSupply"`
		Price                 float64 `json:"price"`
		MarketCap             float64 `json:"marketCap"`
		TradingVolume24       float64 `json:"24hTradingVolume"`
		FullyDilutedMarketCap float64 `json:"fullyDilutedMarketCap"`
	}

	tokenRow struct {
		CreatedAt                *time.Time `db:"created_at"`
		ContractAddress          string     `db:"contract_address"`
		IONConnectAddress        string     `db:"ion_connect_address"`
		Type                     string     `db:"type"`
		Title                    string     `db:"title"`
		Description              string     `db:"description"`
		ImageURL                 string     `db:"image_url"`
		Ticker                   string     `db:"ticker"`
		TotalSupply              string     `db:"total_supply"`
		CreatorMasterPubkey      string     `db:"creator_master_pubkey"`
		CreatorUsername          string     `db:"creator_username"`
		CreatorDisplay           string     `db:"creator_display"`
		CreatorAvatar            string     `db:"creator_avatar"`
		MarketCapUSD             float64    `db:"market_cap_usd"`
		PriceUSD                 float64    `db:"price_usd"`
		Volume24h                float64    `db:"volume_24h"`
		PositionAmountUSD        float64    `db:"position_amount_usd"`
		PositionTotalInvestedUSD float64    `db:"position_total_invested_usd"`
		HoldersCount             int64      `db:"holders_count"`
		CreatorVerified          bool       `db:"creator_verified"`
	}

	tokenVolume24h struct {
		TokenAddress string  `db:"token_address"`
		Volume24h    float64 `db:"volume_24h"`
	}
	tokenSwap struct {
		CreatedAt           *time.Time `db:"created_at"`
		TransactionHash     string     `db:"transaction_hash"`
		ContractAddress     string     `db:"contract_address"`
		IONConnectAddress   string     `db:"ion_connect_address"`
		UserAddress         string     `db:"user_address"`
		Direction           bool       `db:"direction"`
		CreatorMasterPubkey string     `db:"creator_master_pubkey"`
		CreatorUsername     string     `db:"creator_username"`
		CreatorDisplay      string     `db:"creator_display"`
		CreatorVerified     bool       `db:"creator_verified"`
		CreatorAvatar       string     `db:"creator_avatar"`
		HolderMasterPubkey  string     `db:"holder_master_pubkey"`
		HolderUsername      string     `db:"holder_username"`
		HolderDisplay       string     `db:"holder_display"`
		HolderVerified      bool       `db:"holder_verified"`
		HolderAvatar        string     `db:"holder_avatar"`
		Input               uint64     `db:"input_amount"`
		Output              uint64     `db:"output_amount"`
		PriceUSD            float64    `db:"price_usd"`
		BalanceUSD          float64    `db:"balance_usd"`
		Balance             uint64     `db:"balance"`
	}
	trade struct {
		Timestamp                time.Time       `db:"timestamp"`
		PairAddress              string          `db:"pair_address"`
		ContractAddress          string          `db:"contract_address"`
		ContentIONConnectAddress string          `db:"content_ion_connect_address"`
		BasePriceInUsd           float64         `db:"base_price_in_usd"`
		BaseAmount               questdb.Decimal `db:"base_amount"`
		Amount                   questdb.Decimal `db:"amount"`
		PriceInUsd               *big.Float      `db:"price_in_usd"`
		Type                     TradeType       `db:"trade_type"`
		TraderAddress            string          `db:"trader_address"`
		TransactionHash          string          `db:"transaction_hash"`
	}

	holderWithTokenData struct {
		CreatorMasterPubkey string  `db:"creator_master_pubkey"`
		CreatorUsername     string  `db:"creator_username"`
		CreatorDisplay      string  `db:"creator_display"`
		CreatorAvatar       string  `db:"creator_avatar"`
		TotalSupply         string  `db:"total_supply"`
		HolderMasterPubkey  string  `db:"holder_master_pubkey"`
		HolderUsername      string  `db:"holder_username"`
		HolderDisplay       string  `db:"holder_display"`
		HolderAvatar        string  `db:"holder_avatar"`
		HolderIonConnect    string  `db:"holder_ion_connect"`
		PriceUSD            float64 `db:"price_usd"`
		CreatorVerified     bool    `db:"creator_verified"`
		HolderVerified      bool    `db:"holder_verified"`
	}
)
