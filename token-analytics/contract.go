// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/quicknode"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/time"
)

type (
	TokenAnalytics interface {
		MustStart(ctx context.Context)
	}
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
	}
	tokenAnalytics struct {
		ingestedDataDB  *storage.DB
		processedDataDB storagev3.DB
		shutdown        func() error
		cfg             *config
		wg              *sync.WaitGroup
		bondingCurveABI abi.ABI
		quickNode       quicknode.Client
	}
	txEvent struct {
		*SavePoint
		IngestedAt      *time.Time `db:"ingested_at"`
		ProcessedAt     *time.Time `db:"processed_at"`
		TransactionHash string     `db:"transaction_hash"`
		Address         string     `db:"address"`
		FromAddress     string     `db:"from_address"`
		Data            string     `db:"data"`
		Topics          []string   `db:"topics"`
		Topic0          string     `db:"topic0"`
		StreamID        string     `db:"stream_id"`
		I               int        `db:"i"`
		Removed         bool       `db:"removed"`
	}

	SavePoint struct {
		TransactionIndex uint64 `db:"transaction_index"`
		BlockNumber      uint64 `db:"block_number"`
		LogIndex         uint64 `db:"log_index"`
	}
)
