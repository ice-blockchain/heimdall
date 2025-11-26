// SPDX-License-Identifier: ice License 1.0

package quicknode

import (
	"context"
	_ "embed"
	"text/template"

	"github.com/imroc/req/v3"
	"github.com/jackc/pgx/v5"

	"github.com/ice-blockchain/wintr/time"
)

type (
	Client interface {
		CreateStream(ctx context.Context, streamName, contractAddrToMonitor string) (*Stream, error)
		HealthCheck(ctx context.Context, streamApi bool) error
		CurrentBlockRange() (startBlock, endBlock uint64)
	}
	Stream struct {
		ID        string     `json:"id"`
		CreatedAt *time.Time `json:"created_at"`
		UpdatedAt *time.Time `json:"updated_at"`
		Name      string     `json:"name"`
	}
)

type (
	client struct {
		httpClient                              *req.Client
		config                                  *config
		bondingCurveSmartContractFilterTemplate *template.Template
		erc20SmartContractFilterTemplate        *template.Template
		streamDestination                       *pgx.ConnConfig
		network                                 string
	}

	config struct {
		QuickNode   quickNodeCfg `yaml:"quicknode"   mapstructure:"quicknode"`
		Development bool         `yaml:"development" mapstructure:"development"`
	}
	quickNodeCfg struct {
		APIKey string `yaml:"apiKey" mapstructure:"apiKey"`
		// There is no sense to read history before BondingCurve is deployed - 1
		StartBlock           uint64  `yaml:"startBlock"           mapstructure:"startBlock"`
		EndBlock             *uint64 `yaml:"endBlock,omitempty"   mapstructure:"endBlock"`
		StreamDestinationURL string  `yaml:"streamDestinationUrl" mapstructure:"streamDestinationUrl"`
	}
	createStreamReq struct {
		Name                  string  `json:"name"`
		Network               string  `json:"network"`
		Dataset               string  `json:"dataset"`
		FilterFunction        string  `json:"filter_function"`
		Region                string  `json:"region"`
		StartRange            *uint64 `json:"start_range,omitempty"`
		EndRange              *uint64 `json:"end_range,omitempty"`
		DatasetBatchSize      int     `json:"dataset_batch_size"`
		IncludeStreamMetadata string  `json:"include_stream_metadata"`
		Destination           string  `json:"destination"`
		FixBlockReorgs        int     `json:"fix_block_reorgs"`
		KeepDistanceFromTip   int     `json:"keep_distance_from_tip"`
		ElasticBatchEnabled   bool    `json:"elastic_batch_enabled"`
		NotificationEmail     string  `json:"notification_email"`
		DestinationAttributes struct {
			Username         string `json:"username"`
			Password         string `json:"password"`
			Host             string `json:"host"`
			Port             uint16 `json:"port"`
			TableName        string `json:"table_name"`
			Database         string `json:"database"`
			MaxRetry         int    `json:"max_retry"`
			RetryIntervalSec int    `json:"retry_interval_sec"`
			SslMode          string `json:"sslmode"`
		} `json:"destination_attributes"`
		Status string `json:"status"`
	}
)

var (
	//go:embed .quicknode-streams-filters/bonding_curve_smart_contract.js
	bondingCurveSmartContractFilterTemplate string
)
