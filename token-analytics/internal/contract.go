package internal

import (
	"context"
	_ "embed"
	"text/template"

	"github.com/ice-blockchain/wintr/time"

	"github.com/imroc/req/v3"
	"github.com/jackc/pgx/v5"
)

type (
	QuickNodeClient interface {
		CreateStream(ctx context.Context, streamName, contractAddrToMonitor string) (stream *Stream, err error)
	}
	Stream struct {
		ID        string     `json:"id"`
		CreatedAt *time.Time `json:"created_at"`
		UpdatedAt *time.Time `json:"updated_at"`
		Name      string     `json:"name"`
	}
)

type (
	quickNodeClient struct {
		client         *req.Client
		config         *config
		filterTemplate *template.Template
		destination    *pgx.ConnConfig
	}

	config struct {
		QuickNode quickNodeCfg `yaml:"quickNode" mapstructure:"quickNode"`
	}
	quickNodeCfg struct {
		APIKey  string `yaml:"apiKey" mapstructure:"apiKey"`
		Network string `yaml:"network" mapstructure:"network"`
		// There is no sense to read history before BondingCurve is deployed - 1
		StartBlock        uint   `yaml:"startBlock" mapstructure:"startBlock"`
		DestinationUrl    string `yaml:"destinationUrl" mapstructure:"destinationUrl"`
		NotificationEmail string `yaml:"notificationEmail" mapstructure:"notificationEmail"`
	}
	createStreamReq struct {
		Name                  string `json:"name"`
		Network               string `json:"network"`
		Dataset               string `json:"dataset"`
		FilterFunction        string `json:"filter_function"`
		Region                string `json:"region"`
		StartRange            uint   `json:"start_range"`
		EndRange              *uint  `json:"end_range,omitempty"`
		DatasetBatchSize      int    `json:"dataset_batch_size"`
		IncludeStreamMetadata string `json:"include_stream_metadata"`
		Destination           string `json:"destination"`
		FixBlockReorgs        int    `json:"fix_block_reorgs"`
		KeepDistanceFromTip   int    `json:"keep_distance_from_tip"`
		ElasticBatchEnabled   bool   `json:"elastic_batch_enabled"`
		NotificationEmail     string `json:"notification_email"`
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
	//go:embed filter.js
	filterTemplate string
)
