// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/quicknode"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/time"
)

type (
	TokenAnalytics interface {
		MustStart(ctx context.Context)
		Close() error
		Healthcheck(ctx context.Context) error
		UpsertUser(ctx context.Context, id, masterPubkey, username, displayName, avatar string, verified bool, ionConnectRelays []string) error
		SetVerified(ctx context.Context, masterPubkey string) error
	}

	SavePoint struct {
		TransactionIndex uint64 `db:"transaction_index"`
		BlockNumber      uint64 `db:"block_number"`
	}
	JSON map[string]any
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
		Workers              uint   `yaml:"workers"`
		BatchSize            uint   `yaml:"batchSize"`
		BondingCurveContract string `yaml:"bondingCurveContract"`
		StartBlock           uint64 `yaml:"startBlock"`
		Region               string `yaml:"region"`
	}
	tokenAnalytics struct {
		ingestedDataDB  *storage.DB
		processedDataDB storagev3.DB
		shutdown        func() error
		cfg             *config
		wg              *sync.WaitGroup
		bondingCurveABI abi.ABI
		quickNode       quicknode.Client
		metrics         metrics.Registry
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
)
