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

	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rcrowley/go-metrics"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
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
	}

	TokenAnalytics interface {
		Close() error
		HealthCheck(ctx context.Context) error
		MustStart(ctx context.Context)
		GetCommunityTokensByExternalAddresses(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopPlatformHolders *uint32, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		GetCommunityTokensByType(ctx context.Context, viewType string, tokenType *string, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		GetLatestTrades(ctx context.Context, externalAddress string, limit, offset uint64, startFrom *stdlibtime.Time) (trades []*Trade, maxTs stdlibtime.Time, err error)
		GetOHLVCHistory(ctx context.Context, now, startPoint stdlibtime.Time, externalAddress string, interval Interval) (res []*OHLCV, err error)
		SubscribeOHLVC(context.Context, stdlibtime.Time, string, Interval, func(*OHLCV, error)) error
		GetTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress string) (*TradeStats, error)
		UpdateTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress string) (*TradeStats, error)
		CreateViewingSession(ctx context.Context, sessionType, clientIP, deviceKey string, tokenType *string) (sessionID string, ttl uint64, err error)
		GetTopHolders(ctx context.Context, externalAddress string, limit int64) ([]*TopHolderPosition, error)
		GetTokensFromViewingSession(ctx context.Context, sessionType, sessionID, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		UpdateTokenExternalData(ctx context.Context, externalAddress, creatorUsername, creatorDisplayName, creatorAvatar string, creatorVerified bool) error
		GetHolderPositions(ctx context.Context, tokenExternalAddress string, holderExternalAddresses []string) ([]*HolderPosition, error)
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

	Subscriptions interface {
		SubscribeOnSwaps(externalAddress string) <-chan *bondingcurve.LogTokenSwapped
	}
	Notifier interface {
		NotifySwap(ev *bondingcurve.LogTokenSwapped)
	}
)

const (
	TokenTypeProfile = "profile"
	TokenTypePost    = "post"
	TokenTypeArticle = "article"
	TokenTypeVideo   = "video"
	TokenTypeAnyPost = "anyPost"

	TokenTypeLatest               = "latest"
	TokenTypeFeatured             = "featured"
	TokenTypeTop                  = "top"
	TokenTypeTrending             = "trending"
	TokenTypeBondingCurveProgress = "bondingCurveProgress"
)

var (
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
	_ UserRepository = dummyUserRepository{}
)

const (
	applicationYamlKey = "token-analytics"
	tradeTypeBuy       = TradeType("buy")
	tradeTypeSell      = TradeType("sell")

	volumeUpdateInterval                     = 1 * stdlibtime.Minute
	volume24hMaterializedViewRefreshInterval = 30 * stdlibtime.Second

	globalTopSetKey                  = "token_analytics:global:top"
	globalTrendingSetKey             = "token_analytics:global:trending"
	globalBondingCurveProgressSetKey = "token_analytics:global:bonding_curve_progress"

	globalTopProfileSetKey = "token_analytics:global:top:profile"
	globalTopPostSetKey    = "token_analytics:global:top:post"
	globalTopVideoSetKey   = "token_analytics:global:top:video"
	globalTopArticleSetKey = "token_analytics:global:top:article"
	globalTopAnyPostSetKey = "token_analytics:global:top:anyPost"

	globalTrendingProfileSetKey = "token_analytics:global:trending:profile"
	globalTrendingPostSetKey    = "token_analytics:global:trending:post"
	globalTrendingVideoSetKey   = "token_analytics:global:trending:video"
	globalTrendingArticleSetKey = "token_analytics:global:trending:article"
	globalTrendingAnyPostSetKey = "token_analytics:global:trending:anyPost"

	globalBondingCurveProgressProfileSetKey = "token_analytics:global:bonding_curve_progress:profile"
	globalBondingCurveProgressPostSetKey    = "token_analytics:global:bonding_curve_progress:post"
	globalBondingCurveProgressVideoSetKey   = "token_analytics:global:bonding_curve_progress:video"
	globalBondingCurveProgressArticleSetKey = "token_analytics:global:bonding_curve_progress:article"
	globalBondingCurveProgressAnyPostSetKey = "token_analytics:global:bonding_curve_progress:anyPost"

	userSessionKeyPrefix    = "token_analytics:session:%s:%s"  // {type}:{sessionID}
	userIdentifierMapPrefix = "token_analytics:user_map:%s:%s" // {type}:{IP:DeviceKey} -> sessionID

	sessionTypeTop                  = "top"
	sessionTypeTrending             = "trending"
	sessionTypeBondingCurveProgress = "bondingCurveProgress"

	defaultViewingSessionTTL = 5 * stdlibtime.Minute

	schemeMigrationTableName = "wintr_token_analytics_scheme_migrations"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

type (
	config struct {
		IONTokenAddress string `yaml:"ionTokenAddress"`
		BondingCurve    struct {
			SmartContractAddress string `yaml:"smartContractAddress"`
		} `yaml:"bondingCurve" mapstructure:"bondingCurve"`
		Workers   uint `yaml:"workers"`
		BatchSize uint `yaml:"batchSize"`
	}
	dummyUserRepository struct{}
	tokenAnalytics      struct {
		processedDataDB storagev3.DB
		quickNode       quicknode.Client
		metrics         metrics.Registry
		ingestedDataDB  *storage.DB
		questDB         *questdb.DB
		shutdown        func() error
		cfg             *config
		wg              *sync.WaitGroup
		ionPriceUSD     *atomic.Pointer[float64]
		// TODO: xmap for latest creator token prices to calc content token price
		bondingCurveContractAddress string
		ohclvRecentData             *xsync.Map[string, *recentCandlestick]
		subscriptions               interface {
			Subscriptions
			Notifier
		}
	}
	tokenAnalyticsUsers struct {
		ingestedDataDB *storage.DB
		shutdown       func() error
		cfg            *config
	}
	subscriptions struct {
		swaps    chan *bondingcurve.LogTokenSwapped
		swapSubs *xsync.Map[string, chan *bondingcurve.LogTokenSwapped]
	}
	txEvent struct {
		BlockTimestamp   *time.Time  `db:"block_timestamp"`
		TransactionHash  string      `db:"transaction_hash"`
		FromAddress      string      `db:"from_address"`
		ToAddress        string      `db:"to_address"`
		ChainID          string      `db:"chain_id"`
		Value            string      `db:"value"`
		Input            string      `db:"input"`
		Logs             txEventLogs `db:"logs"`
		TransactionIndex uint64      `db:"transaction_index"`
		BlockNumber      uint64      `db:"block_number"`
	}

	txEventLogs   []JSON
	savePointData struct {
		WorkerIdx        uint   `redis:"-"`
		BlockNumber      uint64 `redis:"block_number"`
		TransactionIndex uint64 `redis:"transaction_index"`
		LogIndex         uint64 `redis:"log_index"`
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
		CreatedAt                    *time.Time `db:"created_at"`
		UpdatedAt                    *time.Time `db:"updated_at"`
		LogIndex                     *int64     `db:"log_index"`
		ContractAddress              string     `db:"contract_address"`
		ExternalAddress              string     `db:"external_address"`
		Platform                     string     `db:"platform"`
		Type                         string     `db:"type"`
		Title                        string     `db:"title"`
		Description                  string     `db:"description"`
		ImageURL                     string     `db:"image_url"`
		Ticker                       string     `db:"ticker"`
		TotalSupply                  string     `db:"total_supply"`
		CreatorMasterPubkey          string     `db:"creator_master_pubkey"`
		CreatorUsername              string     `db:"creator_username"`
		CreatorDisplay               string     `db:"creator_display"`
		CreatorAvatar                string     `db:"creator_avatar"`
		BaseToken                    string     `db:"base_token"`
		PairId                       string     `db:"pair_id"`
		MarketCapUSD                 float64    `db:"market_cap_usd"`
		PriceUSD                     float64    `db:"price_usd"`
		Volume24h                    float64    `db:"volume_24h"`
		PositionAmountUSD            float64    `db:"position_amount_usd"`
		PositionTotalInvestedUSD     float64    `db:"position_total_invested_usd"`
		HoldersCount                 int64      `db:"holders_count"`
		PlatformHoldersCount         int64      `db:"platform_holders_count"`
		BondingCurveCurrentAmount    string     `db:"bonding_curve_current_amount"`
		BondingCurveGoalAmount       string     `db:"bonding_curve_goal_amount"`
		BondingCurveCurrentAmountUSD float64    `db:"bonding_curve_current_amount_usd"`
		BondingCurveGoalAmountUSD    float64    `db:"bonding_curve_goal_amount_usd"`
		CreatorVerified              bool       `db:"creator_verified"`
	}

	tokenVolume24h struct {
		TokenAddress string  `db:"token_address"`
		Volume24h    float64 `db:"volume_24h"`
	}

	holderPositionRow struct {
		MasterPubkey     string  `db:"master_pubkey"`
		Username         string  `db:"username"`
		DisplayName      string  `db:"display_name"`
		Avatar           string  `db:"avatar"`
		Verified         bool    `db:"verified"`
		ExternalAddress  string  `db:"external_address"`
		Amount           string  `db:"amount"`
		TotalInvestedUSD float64 `db:"total_invested_usd"`
		PriceUSD         float64 `db:"price_usd"`
	}

	tokenSwap struct {
		CreatedAt              *time.Time `db:"created_at"`
		TransactionHash        string     `db:"transaction_hash"`
		ContractAddress        string     `db:"contract_address"`
		ExternalAddress        string     `db:"external_address"`
		UserAddress            string     `db:"user_address"`
		CreatorMasterPubkey    string     `db:"creator_master_pubkey"`
		CreatorUsername        string     `db:"creator_username"`
		CreatorDisplay         string     `db:"creator_display"`
		CreatorAvatar          string     `db:"creator_avatar"`
		CreatorExternalAddress string     `db:"creator_external_address"`
		HolderMasterPubkey     string     `db:"holder_master_pubkey"`
		HolderUsername         string     `db:"holder_username"`
		HolderDisplay          string     `db:"holder_display"`
		HolderAvatar           string     `db:"holder_avatar"`
		HolderExternalAddress  string     `db:"holder_external_address"`
		Input                  string     `db:"input_amount"`
		Output                 string     `db:"output_amount"`
		PriceUSD               float64    `db:"price_usd"`
		BalanceUSD             float64    `db:"balance_usd"`
		Balance                string     `db:"balance"`
		Direction              bool       `db:"direction"`
		CreatorVerified        bool       `db:"creator_verified"`
		HolderVerified         bool       `db:"holder_verified"`
	}
	trade struct {
		Timestamp       time.Time       `db:"timestamp"`
		PriceInUsd      *big.Float      `db:"price_in_usd"`
		PairAddress     string          `db:"pair_address"`
		ContractAddress string          `db:"contract_address"`
		ExternalAddress string          `db:"external_address"`
		Type            TradeType       `db:"trade_type"`
		TraderAddress   string          `db:"trader_address"`
		TransactionHash string          `db:"transaction_hash"`
		BasePriceInUsd  float64         `db:"base_price_in_usd"`
		BaseAmount      questdb.Decimal `db:"base_amount"`
		Amount          questdb.Decimal `db:"amount"`
	}

	holderWithTokenData struct {
		CreatorMasterPubkey   string  `db:"creator_master_pubkey"`
		CreatorUsername       string  `db:"creator_username"`
		CreatorDisplay        string  `db:"creator_display"`
		CreatorAvatar         string  `db:"creator_avatar"`
		TotalSupply           string  `db:"total_supply"`
		HolderMasterPubkey    string  `db:"holder_master_pubkey"`
		HolderUsername        string  `db:"holder_username"`
		HolderDisplay         string  `db:"holder_display"`
		HolderAvatar          string  `db:"holder_avatar"`
		HolderExternalAddress string  `db:"holder_external_address"`
		PriceUSD              float64 `db:"price_usd"`
		CreatorVerified       bool    `db:"creator_verified"`
		HolderVerified        bool    `db:"holder_verified"`
	}
	recentCandlestick struct {
		o               atomic.Pointer[OHLCV]
		interval        Interval
		onceStartTicker sync.Once
	}

	holderMetadata struct {
		HolderMasterPubkey    string `json:"holder_master_pubkey"`
		HolderUsername        string `json:"holder_username"`
		HolderDisplay         string `json:"holder_display"`
		HolderVerified        bool   `json:"holder_verified"`
		HolderAvatar          string `json:"holder_avatar"`
		HolderExternalAddress string `json:"holder_external_address"`
	}

	tokenRowWithTopPlatformHolders struct {
		tokenRow
		TopPlatformHoldersJSON string `db:"top_platform_holders_json"`
	}
)
