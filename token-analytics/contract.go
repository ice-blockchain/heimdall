// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"
	"sync"
	"sync/atomic"

	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/quicknode"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/time"
)

type (
	UserRepository interface {
		Close() error
		HealthCheck(ctx context.Context) error
		UpsertUser(ctx context.Context, id, masterPubkey, username, displayName, avatar string, verified bool, ionConnectRelays []string) error
		SetVerified(ctx context.Context, masterPubkey string) error
	}

	TokenAnalytics interface {
		Close() error
		HealthCheck(ctx context.Context) error
		UserRepository
		MustStart(ctx context.Context)
		GetCommunityTokens(ctx context.Context, ionConnectAddresses []string, requestorMasterPubkey string) ([]*CommunityToken, error)
	}

	SavePoint struct {
		TransactionIndex uint64 `db:"transaction_index"`
		BlockNumber      uint64 `db:"block_number"`
	}
	JSON map[string]any
)

const (
	TokenTypeProfile = "profile"
	TokenTypePost    = "post"
	TokenTypeArticle = "article"
	TokenTypeVideo   = "video"
)

var (
	//go:embed DDL.sql
	sourceDDL string
)

const (
	applicationYamlKey = "token-analytics"
)

type (
	config struct {
		Workers         uint   `yaml:"workers"`
		BatchSize       uint   `yaml:"batchSize"`
		StartBlock      uint64 `yaml:"startBlock"`
		Region          string `yaml:"region"`
		IONTokenAddress string `yaml:"ionTokenAddress"`
	}
	tokenAnalytics struct {
		bondingCurveContractAddress string
		ingestedDataDB              *storage.DB
		processedDataDB             storagev3.DB
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
		ContractAddress          string  `db:"contract_address"`
		IONConnectAddress        string  `db:"ion_connect_address"`
		Type                     string  `db:"type"`
		Title                    string  `db:"title"`
		Description              string  `db:"description"`
		ImageURL                 string  `db:"image_url"`
		Ticker                   string  `db:"ticker"`
		TotalSupply              string  `db:"total_supply"`
		CreatorMasterPubkey      string  `db:"creator_master_pubkey"`
		CreatorUsername          string  `db:"creator_username"`
		CreatorDisplay           string  `db:"creator_display"`
		CreatorVerified          bool    `db:"creator_verified"`
		CreatorAvatar            string  `db:"creator_avatar"`
		MarketCapUSD             float64 `db:"market_cap_usd"`
		PriceUSD                 float64 `db:"price_usd"`
		Volume24h                float64 `db:"volume_24h"`
		HoldersCount             int64   `db:"holders_count"`
		PositionAmountUSD        float64 `db:"position_amount_usd"`
		PositionTotalInvestedUSD float64 `db:"position_total_invested_usd"`
	}
)
