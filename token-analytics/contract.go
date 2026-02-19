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

	"github.com/elliotchance/orderedmap/v3"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/cdn"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/llm"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/riverqueue"
	"github.com/ice-blockchain/wintr/time"
)

type (
	UserRecord struct {
		ID               string   `db:"id"`
		MasterPubkey     string   `db:"master_pubkey"`
		ExternalAddress  string   `db:"external_address"`
		Username         string   `db:"username"`
		DisplayName      string   `db:"display_name"`
		Avatar           string   `db:"avatar"`
		Lookup           string   `db:"lookup"`
		IONConnectRelays []string `db:"ion_connect_relays"`
		Verified         bool     `db:"verified"`
		PlatformGroup    string   `db:"platform_group"`
	}

	UserRepository interface {
		Close() error
		HealthCheck(ctx context.Context) error
		UpsertUser(ctx context.Context, id, masterPubkey, contentAuthorID, username, displayName, avatar string, verified *bool, ionConnectRelays []string) error
		UpdateUserProfileAndToken(ctx context.Context, masterPubkey, username, displayName, avatar string) (coins.TokenAnalyticsToken, error)
		SetVerified(ctx context.Context, masterPubkey string) error
		GetUser(ctx context.Context, masterPubkey string) (*UserRecord, error)
		ValidateTransaction(txPayload accounts.TransactionPayload) error
	}
	CoinImport interface {
		ImportTokenizedCommunitiesCoin(ctx context.Context, coin coins.TokenAnalyticsToken) (*coins.Coin, error)
	}
	PriceSync interface {
		UpdateBNBPrice(ctx context.Context, price float64) error
		GetTokenUpdates(ctx context.Context, contractAddresses []string) (map[string]coins.TokenAnalyticsToken, error)
	}
	TokenAnalytics interface {
		Close() error
		HealthCheck(ctx context.Context) error
		MustStart(ctx context.Context)
		GetCommunityTokensByExternalAddresses(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopPlatformHolders *uint32, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		GetCommunityTokensByHolder(ctx context.Context, holderExternalAddress, requestorMasterPubkey string, limit, offset uint64) ([]*CommunityToken, uint64, error)
		GetCommunityTokensByType(ctx context.Context, viewType string, tokenType *string, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		GetLatestTrades(ctx context.Context, externalAddress string, limit, offset uint64, startFrom *stdlibtime.Time) (trades []*Trade, maxTs stdlibtime.Time, err error)
		SubscribeLatestTrades(ctx context.Context, externalAddress, user string, addToStream func(*Trade, error)) error
		GetOHLVCHistory(ctx context.Context, now stdlibtime.Time, externalAddress string, interval Interval, limit, offset uint64) (res []*OHLCV, err error)
		SubscribeOHLVC(ctx context.Context, now stdlibtime.Time, externalAddress, user string, interval Interval, addToStream func(*OHLCV, error)) error
		GetTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress string) (*TradeStats, error)
		SubscribeTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress, user string, addToStream func(*TradeStats, error)) error
		CreateViewingSession(ctx context.Context, sessionType, clientIP, deviceKey string, tokenType *string) (sessionID string, ttl uint64, err error)
		GetTopHolders(ctx context.Context, externalAddress string, limit int64) ([]*TopHolderPosition, error)
		GetTokensFromViewingSession(ctx context.Context, sessionType, sessionID, keyword string, limit, offset uint64) ([]*CommunityToken, error)
		UpdateLoggedInUserProfile(ctx context.Context,
			masterPubkey, userExternalAddress, userUsername, userDisplayName, userAvatar string, userVerified bool,
			userContentId string) error
		UpdateTokenExternalData(ctx context.Context,
			tokenExternalAddress, postAuthorExternalAddress, postAuthorUsername, postAuthorDisplayName, postAuthorAvatar string, postAuthorVerified bool,
			userContentId, tokenImageUrl string) error
		GetHolderPositions(ctx context.Context, tokenExternalAddress string, holderExternalAddresses []string) ([]*HolderPosition, error)
		GenerateTokenSuggestion(ctx context.Context, data *CreationDetailsData) (*SuggestedCreationDetails, error)
		GetBondingCurveProgress(ctx context.Context, externalAddress string) (*BondingCurveProgress, error)
		SubscribeBondingCurveProgress(ctx context.Context, externalAddress, user string, addToStream func(*BondingCurveProgress, error)) error
		GetTokenPricing(ctx context.Context, externalAddress string, tradeType TradeType, amount *big.Int, amountBNB *big.Int, amountUSD float64) (pricing *Pricing, err error)
		GetCommunityTokensByRewardsDistribution(ctx context.Context, referenceDate stdlibtime.Time, limit, offset uint64) ([]*CommunityToken, error)
		GetGlobalTokenStatistics(ctx context.Context, interval string) (*GlobalTokenStats, error)
	}
	Pricing struct {
		AmountInBase       *big.Int
		AmountInBNB        *big.Int
		FeeSponsorAddress  string
		FeeSponsorId       string
		AmountInUSD        float64
		IonPriceInUSD      float64
		BNBPriceInUSD      float64
		ContentTokenParams *StartTokenParams
		CreatorTokenParams *StartTokenParams
	}

	StartTokenParams struct {
		BondingCurveAlgAddress string  `json:"bondingCurveAlgAddress"` // Pricing model
		InitialPrice           string  `json:"initialPrice"`
		InitialPriceUSD        float64 `json:"initialPriceUSD"`
		FinalPrice             string  `json:"finalPrice"`
		FinalPriceUSD          float64 `json:"finalPriceUSD"`
		EmissionVolume         string  `json:"emissionVolume"`
	}

	SavePoint struct {
		TransactionIndex uint64 `db:"transaction_index"`
		BlockNumber      uint64 `db:"block_number"`
		BlockTime        int64
	}

	ViewingSession struct {
		ID        string `redis:"id"`
		Type      string `redis:"type"`
		UserIP    string `redis:"user_ip"`
		CreatedAt int64  `redis:"created_at"`
		TTL       int64  `redis:"ttl"`
	}
	TradeType  string
	JSON       map[string]any
	Interval   string
	WindowSize stdlibtime.Duration

	GlobalTokenStats struct {
		Launched    uint64  `json:"launched" db:"launched" redis:"launched"`
		Migrated    uint64  `json:"migrated" db:"migrated" redis:"migrated"`
		TotalVolume float64 `json:"volume" db:"total_volume" redis:"total_volume"`
	}
)

const (
	TokenTypeProfile = "profile"
	TokenTypePost    = "post"
	TokenTypeArticle = "article"
	TokenTypeVideo   = "video"
	TokenTypeAnyPost = "anyPost"
	TokenTypeXcom    = "xcom"

	TokenTypeLatest               = "latest"
	TokenTypeFeatured             = "featured"
	TokenTypeTop                  = "top"
	TokenTypeTrending             = "trending"
	TokenTypeBondingCurveProgress = "bondingCurveProgress"
	TokenTypeRewardsDistribution  = "rewardsDistribution"
)

var (
	validIntervals = map[Interval]WindowSize{
		Interval("15s"): WindowSize(1 * stdlibtime.Hour),
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
	allTokenTypes                = []string{TokenTypeProfile, TokenTypePost, TokenTypeArticle, TokenTypeVideo}
	_             UserRepository = dummyUserRepository{}
)

const (
	applicationYamlKey = "token-analytics"
	TradeTypeBuy       = TradeType("buy")
	TradeTypeSell      = TradeType("sell")

	volumeUpdateInterval                     = 1 * stdlibtime.Minute
	volume24hMaterializedViewRefreshInterval = 30 * stdlibtime.Second

	analyticsSnapshotCheckInterval = 1 * stdlibtime.Minute
	HourlyRankingTopN              = 100

	hourKeyFormat = "2006-01-02T15"

	processedSnapshotsSetKey = "token_analytics:processed_snapshots"

	globalTopSetKey                  = "token_analytics:global:top"
	globalTrendingSetKey             = "token_analytics:global:trending"
	globalBondingCurveProgressSetKey = "token_analytics:global:bonding_curve_progress"

	tokenBondingCurveUpdatesChannel = "token_bonding_curve_updates"
	userBalanceUpdatesChannel       = "user_balance_updates"

	globalTopProfileSetKey = "token_analytics:global:top:profile"
	globalTopPostSetKey    = "token_analytics:global:top:post"
	globalTopVideoSetKey   = "token_analytics:global:top:video"
	globalTopArticleSetKey = "token_analytics:global:top:article"
	globalTopAnyPostSetKey = "token_analytics:global:top:anyPost"
	globalTopXcomSetKey    = "token_analytics:global:top:xcom"

	globalTrendingProfileSetKey = "token_analytics:global:trending:profile"
	globalTrendingPostSetKey    = "token_analytics:global:trending:post"
	globalTrendingVideoSetKey   = "token_analytics:global:trending:video"
	globalTrendingArticleSetKey = "token_analytics:global:trending:article"
	globalTrendingAnyPostSetKey = "token_analytics:global:trending:anyPost"
	globalTrendingXcomSetKey    = "token_analytics:global:trending:xcom"

	globalBondingCurveProgressProfileSetKey = "token_analytics:global:bonding_curve_progress:profile"
	globalBondingCurveProgressPostSetKey    = "token_analytics:global:bonding_curve_progress:post"
	globalBondingCurveProgressVideoSetKey   = "token_analytics:global:bonding_curve_progress:video"
	globalBondingCurveProgressArticleSetKey = "token_analytics:global:bonding_curve_progress:article"
	globalBondingCurveProgressAnyPostSetKey = "token_analytics:global:bonding_curve_progress:anyPost"
	globalBondingCurveProgressXcomSetKey    = "token_analytics:global:bonding_curve_progress:xcom"

	userSessionKeyPrefix    = "token_analytics:session:%s:%s"  // {type}:{sessionID}
	userIdentifierMapPrefix = "token_analytics:user_map:%s:%s" // {type}:{IP:DeviceKey} -> sessionID

	sessionTypeTop                  = "top"
	sessionTypeTrending             = "trending"
	sessionTypeBondingCurveProgress = "bondingCurveProgress"

	defaultViewingSessionTTL = 5 * stdlibtime.Minute

	schemeMigrationTableName = "wintr_token_analytics_scheme_migrations"

	bondingCurveTopHolderDisplayName = "Bonding Curve"
	burnedTopHolderDisplayName       = "Burned"

	bondingCurveTopHolderAvatar = "https://cdn.ice.io/online+/assets/coins/bondingCurve.svg"
	burnedTopHolderAvatar       = "https://cdn.ice.io/online+/assets/coins/burned.svg"

	fatAddressHeaderSize    = 64
	feeDestinationCreator   = "creator"
	feeDestinationBurn      = "burn"
	feeDestinationAffiliate = "affiliate"
)

var (
	ErrSessionNotFound  = errors.New("session not found")
	ErrDuplicate        = errors.New("duplicate entry")
	ErrTokenNotFound    = errors.New("token not found")
	ErrValidationFailed = errors.New("validation failed")
)

type (
	config struct {
		IONTokenAddress string     `yaml:"ionTokenAddress"`
		LLM             llm.Config `yaml:"llm" mapstructure:"llm"`
		CDN             cdn.Config `yaml:"cdn" mapstructure:"cdn"`
		BondingCurve    struct {
			SmartContractAddress                string                         `yaml:"smartContractAddress"`
			BurnAddress                         string                         `yaml:"burnAddress"`
			TokenFactorySmartContractAddress    string                         `yaml:"tokenFactorySmartContractAddress"`
			BondingCurveProgressUpdateFrequency stdlibtime.Duration            `yaml:"bondingCurveProgressUpdateFrequency"`
			CreateTokenDefaults                 map[string]createTokenDefaults `yaml:"createTokenDefaults" mapstructure:"createTokenDefaults"`
		} `yaml:"bondingCurve" mapstructure:"bondingCurve"`
		RiverQueue struct {
			QueueName       string              `yaml:"queueName,omitempty"`
			MaxQueueWorkers int                 `yaml:"maxQueueWorkers,omitempty"`
			JobMaxTimeout   stdlibtime.Duration `yaml:"jobMaxTimeout,omitempty"`
		} `yaml:"riverQueue" mapstructure:"riverQueue"`
		Storage               storage.Cfg `yaml:"wintr/connectors/storage/v2" mapstructure:"wintr/connectors/storage/v2"`
		Workers               uint        `yaml:"workers"`
		BatchSize             uint        `yaml:"batchSize"`
		IdentityServiceURL    string      `yaml:"identityServiceUrl"`
		IdentityServiceAPIKey string      `yaml:"identityServiceApiKey"`
		EnableDummyGenerator  bool        `yaml:"enableDummyGenerator"`
	}
	createTokenDefaults struct {
		InitialPrice           string `yaml:"initialPrice"`
		FinalPrice             string `yaml:"finalPrice"`
		EmissionVolume         string `yaml:"emissionVolume"`
		BondingCurveAlgAddress string `yaml:"bondingCurveAlgAddress"`
		FeeSponsorAddress      string `yaml:"feeSponsorAddress"`
		FeeSponsorId           string `yaml:"feeSponsorId"`
	}

	dummyUserRepository struct{}
	tokenAnalytics      struct {
		processedDataDB       storagev3.DB
		metrics               metrics.Registry
		ingestedDataDB        *storage.DB
		questDB               *questdb.DB
		shutdown              func() error
		cfg                   *config
		wg                    *sync.WaitGroup
		bondingCurve          bondingcurve.BondingCurve
		riverClient           riverqueue.Client
		generator             *dummyDataGenerator
		ionPriceUSD           *atomic.Pointer[float64]
		bnbPriceUSD           *atomic.Pointer[float64]
		creatorTokenPricesUSD *xsync.Map[string, float64]
		identityClient        *identityClient
		llmClient             llm.Client
		cdnClient             cdn.Client
		coins                 CoinImport
		// TODO: xmap for latest creator token prices to calc content token price
		bondingCurveContractAddress string
		tokenFactoryContractAddress string
		ohclvRecentData             *xsync.Map[string, *recentCandlestick]
		tradingStatsRecentData      *xsync.Map[string, *recentTradeStats]
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
		Dummy            bool        `db:"dummy"`
	}

	txEventLogs   []JSON
	savePointData struct {
		WorkerIdx        uint   `redis:"-"`
		BlockNumber      uint64 `redis:"block_number"`
		TransactionIndex uint64 `redis:"transaction_index"`
		LogIndex         uint64 `redis:"log_index"`
		UpdatedAt        int64  `redis:"updated_at"`
		BlockTime        int64  `redis:"blockTime"`
		IsDummy          bool   `redis:"-"` // Flag to distinguish dummy vs normal savepoint
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
		CreatedAt                     *time.Time `db:"created_at"`
		UpdatedAt                     *time.Time `db:"updated_at"`
		LogIndex                      *int64     `db:"log_index"`
		ContractAddress               string     `db:"contract_address"`
		ExternalAddress               string     `db:"external_address"`
		Platform                      string     `db:"platform"`
		Type                          string     `db:"type"`
		Title                         string     `db:"title"`
		Description                   string     `db:"description"`
		ImageURL                      string     `db:"image_url"`
		Ticker                        string     `db:"ticker"`
		TotalSupply                   string     `db:"total_supply"`
		ContentAuthorID               *string    `db:"content_author_id"`
		CreatorUsername               *string    `db:"creator_username"`
		CreatorDisplay                *string    `db:"creator_display"`
		CreatorAvatar                 *string    `db:"creator_avatar"`
		CreatorExternalAddress        *string    `db:"creator_external_address"`
		CreatorPlatform               *string    `db:"creator_platform"`
		CreatorBnbBscAddress          *string    `db:"creator_bnb_bsc_address"`
		IonConnectAddress             *string    `db:"ion_connect_address"`
		BaseToken                     string     `db:"base_token"`
		PriceModel                    string     `db:"price_model"`
		PairId                        string     `db:"pair_id"`
		MarketCapUSD                  float64    `db:"market_cap_usd"`
		PriceUSD                      float64    `db:"price_usd"`
		LiquidityUSD                  float64    `db:"liquidity_usd"`
		Volume24h                     float64    `db:"volume_24h"`
		PositionAmount                string     `db:"position_amount"`
		PositionAmountUSD             float64    `db:"position_amount_usd"`
		PositionTotalInvestedUSD      float64    `db:"position_total_invested_usd"`
		PositionTotalRealizedUSD      float64    `db:"position_total_realized_usd"`
		HoldersCount                  int64      `db:"holders_count"`
		PlatformHoldersCount          int64      `db:"platform_holders_count"`
		BondingCurveCurrentAmount     string     `db:"bonding_curve_current_amount"`
		BondingCurveGoalAmount        string     `db:"bonding_curve_goal_amount"`
		BondingCurveRaisedAmount      string     `db:"bonding_curve_raised_amount"`
		BondingCurveMigrated          bool       `db:"bonding_curve_migrated"`
		BondingCurveCurrentAmountUSD  float64    `db:"bonding_curve_current_amount_usd"`
		BondingCurveGoalAmountUSD     float64    `db:"bonding_curve_goal_amount_usd"`
		CreatorVerified               *bool      `db:"creator_verified"`
		LauncherUsername              *string    `db:"launcher_username"`
		LauncherDisplay               *string    `db:"launcher_display"`
		LauncherAvatar                *string    `db:"launcher_avatar"`
		LauncherExternalAddress       *string    `db:"launcher_external_address"`
		LauncherPlatform              *string    `db:"launcher_platform"`
		LauncherVerified              *bool      `db:"launcher_verified"`
		LauncherBlockchainAddress     *string    `db:"launcher_blockchain_address"`
		TokenHoldingsCount            uint64     `db:"token_holdings_count"`
		CreatorTokenTicker            *string    `db:"creator_token_ticker"`
		CreatorTokenTitle             *string    `db:"creator_token_title"`
		CreatorTokenDescription       *string    `db:"creator_token_description"`
		CreatorTokenImageURL          *string    `db:"creator_token_image_url"`
		CreatorTokenCreatedAt         *time.Time `db:"creator_token_created_at"`
		CreatorTokenContractAddress   *string    `db:"creator_token_contract_address"`
		CreatorTokenExternalAddress   *string    `db:"creator_token_external_address"`
		CreatorTokenPlatform          *string    `db:"creator_token_platform"`
		CreatorTokenIonConnectAddress *string    `db:"creator_token_ion_connect_address"`
	}

	tokenVolume24h struct {
		TokenAddress string  `db:"token_address"`
		Volume24h    float64 `db:"volume_24h"`
	}

	holderPositionRow struct {
		MasterPubkey     *string `db:"master_pubkey"`
		Username         *string `db:"username"`
		DisplayName      *string `db:"display_name"`
		Avatar           *string `db:"avatar"`
		Verified         *bool   `db:"verified"`
		ExternalAddress  *string `db:"external_address"`
		Platform         *string `db:"platform"`
		Amount           string  `db:"amount"`
		TotalInvestedUSD float64 `db:"total_invested_usd"`
		TotalRealizedUSD float64 `db:"total_realized_usd"`
		PriceUSD         float64 `db:"price_usd"`
	}

	tokenSwap struct {
		CreatedAt              *time.Time `db:"created_at"`
		TransactionHash        string     `db:"transaction_hash"`
		ContractAddress        string     `db:"contract_address"`
		ExternalAddress        string     `db:"external_address"`
		Platform               string     `db:"platform"`
		UserBlockchainAddress  string     `db:"user_blockchain_address"`
		ContentAuthorID        *string    `db:"content_author_id"`
		CreatorUsername        *string    `db:"creator_username"`
		CreatorDisplay         *string    `db:"creator_display"`
		CreatorAvatar          *string    `db:"creator_avatar"`
		CreatorExternalAddress *string    `db:"creator_external_address"`
		CreatorPlatform        *string    `db:"creator_platform"`
		CreatorBnbBscAddress   *string    `db:"creator_bnb_bsc_address"`
		HolderMasterPubkey     *string    `db:"holder_master_pubkey"`
		HolderUsername         *string    `db:"holder_username"`
		HolderDisplay          *string    `db:"holder_display"`
		HolderAvatar           *string    `db:"holder_avatar"`
		HolderExternalAddress  *string    `db:"holder_external_address"`
		HolderPlatform         *string    `db:"holder_platform"`
		Input                  string     `db:"input_amount"`
		Output                 string     `db:"output_amount"`
		PriceUSD               float64    `db:"price_usd"`
		BalanceUSD             float64    `db:"balance_usd"`
		Balance                string     `db:"balance"`
		Direction              bool       `db:"direction"`
		CreatorVerified        *bool      `db:"creator_verified"`
		HolderVerified         *bool      `db:"holder_verified"`
	}
	trade struct {
		Timestamp       time.Time       `db:"timestamp"`
		PriceInUsd      *big.Float      `db:"price_in_usd"`
		MarketcapUsd    *big.Float      `db:"price_in_usd"`
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
		ContentAuthorID        *string `db:"content_author_id"`
		CreatorUsername        *string `db:"creator_username"`
		CreatorDisplay         *string `db:"creator_display"`
		CreatorAvatar          *string `db:"creator_avatar"`
		CreatorExternalAddress *string `db:"creator_external_address"`
		CreatorPlatform        *string `db:"creator_platform"`
		CreatorBnbBscAddress   *string `db:"creator_bnb_bsc_address"`
		CreatorFees            string  `db:"creator_fees"`
		TotalSupply            string  `db:"total_supply"`
		BondingCurveMigrated   bool    `db:"bonding_curve_migrated"`
		PairId                 string  `db:"pair_id"`
		BaseToken              string  `db:"base_token"`
		HolderMasterPubkey     *string `db:"holder_master_pubkey"`
		HolderUsername         *string `db:"holder_username"`
		HolderDisplay          *string `db:"holder_display"`
		HolderAvatar           *string `db:"holder_avatar"`
		HolderExternalAddress  *string `db:"holder_external_address"`
		HolderBnbBscAddress    *string `db:"holder_bnb_bsc_address"`
		HolderPlatform         *string `db:"holder_platform"`
		PriceUSD               float64 `db:"price_usd"`
		CreatorVerified        *bool   `db:"creator_verified"`
		HolderVerified         *bool   `db:"holder_verified"`
	}
	recentCandlestick struct {
		o               atomic.Pointer[OHLCV]
		interval        Interval
		onceStartTicker sync.Once
	}
	recentTradeStats struct {
		stats           *TradeStats
		initTime        int64
		mx              sync.Mutex
		expirations5M   *orderedmap.OrderedMap[int64, TradeStatsAggregate]
		expirations1H   *orderedmap.OrderedMap[int64, TradeStatsAggregate]
		expirations6H   *orderedmap.OrderedMap[int64, TradeStatsAggregate]
		expirations24H  *orderedmap.OrderedMap[int64, TradeStatsAggregate]
		onceStartTicker sync.Once
	}
	holderMetadata struct {
		HolderMasterPubkey    *string `json:"holder_master_pubkey"`
		HolderUsername        *string `json:"holder_username"`
		HolderDisplay         *string `json:"holder_display"`
		HolderVerified        *bool   `json:"holder_verified"`
		HolderAvatar          *string `json:"holder_avatar"`
		HolderExternalAddress *string `json:"holder_external_address"`
		HolderPlatform        *string `json:"holder_platform"`
	}

	tokenRowWithTopPlatformHolders struct {
		tokenRow
		TopPlatformHoldersJSON string `db:"top_platform_holders_json"`
	}

	tokenAndUserInfo struct {
		ContractAddress            string  `db:"contract_address"`
		BaseToken                  string  `db:"base_token"`
		TokenExternalAddress       string  `db:"token_external_address"`
		PairId                     string  `db:"pair_id"`
		UserExternalAddress        string  `db:"user_external_address"`
		Type                       string  `db:"token_type"`
		Platform                   string  `db:"platform"`
		Ticker                     string  `db:"ticker"`
		Title                      string  `db:"title"`
		ImageURL                   string  `db:"image_url"`
		TotalSupply                string  `db:"total_supply"`
		Burned                     string  `db:"burned"`
		PriceUsd                   float64 `db:"price_usd"`
		BaseProfileContractAddress *string `db:"base_profile_contract_address"`
		BaseProfileExternalAddress *string `db:"base_profile_external_address"`
	}
	fee struct {
		Amount float64 `db:"amount"`
	}
	fatAddressToken struct {
		Name            string
		Symbol          string
		ExternalAddress string
		Type            string
		Platform        string
		RawType         byte
		PricingModel    string
		TotalSupply     *big.Int
		StartPrice      *big.Int
		EndPrice        *big.Int
	}
	analyticsSnapshotEntry struct {
		timestamp    stdlibtime.Time
		intervalType string
		launched     int64
		migrated     int64
		totalVolume  float64
	}
	intervalStatsRow struct {
		Launched    uint64  `db:"launched"`
		Migrated    uint64  `db:"migrated"`
		TotalVolume float64 `db:"total_volume"`
	}
	hourlyTokenRanking struct {
		ExternalAddress string  `db:"external_address"`
		Volume1h        float64 `db:"volume_1h"`
	}
)
