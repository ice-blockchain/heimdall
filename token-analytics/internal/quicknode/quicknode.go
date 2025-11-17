// SPDX-License-Identifier: ice License 1.0

package quicknode

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

const (
	networkMainnet = "bnbchain-mainnet"
	networkTestnet = "bnbchain-testnet"
)

func NewClient(ctx context.Context, applicationYamlKey string) Client {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.QuickNode.APIKey == "" || cfg.QuickNode.APIKey == "-" {
		cfg.QuickNode.APIKey = os.Getenv("QUICKNODE_API_KEY")
	}
	conf, err := pgxpool.ParseConfig(cfg.QuickNode.StreamDestinationURL)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to parse destination url"))
	}

	network := networkMainnet
	if cfg.Development {
		network = networkTestnet
		log.Warn("Using testnet network for QuickNode")
	}

	q := &client{
		bondingCurveSmartContractFilterTemplate: template.Must(template.New("bondingCurveSmartContractTemplate").Parse(bondingCurveSmartContractTemplate)),
		httpClient:                              req.C().SetBaseURL("https://api.quicknode.com/"),
		config:                                  &cfg,
		streamDestination:                       conf.ConnConfig,
		network:                                 network,
	}
	if err = q.HealthCheck(ctx); err != nil {
		log.Panic(errors.Wrapf(err, "failed to connect to QuickNode API"))
	}
	return q
}

func (q *client) HealthCheck(ctx context.Context) error {
	if resp, err := q.req(ctx).Get("/streams/rest/v1/streams"); err != nil {
		return errors.Wrapf(err, "failed to get /streams/rest/v1/streams")
	} else if resp.GetStatusCode() >= http.StatusBadRequest {
		return errors.Errorf("failed get /streams/rest/v1/streams with %v", resp.GetStatusCode())
	} else if _, err2 := resp.ToBytes(); err2 != nil {
		return errors.Wrapf(err2, "failed to read body of /streams/rest/v1/streams")
	} else {
		return nil
	}
}

func (q *client) req(ctx context.Context) *req.Request {
	return q.httpClient.R().
		SetContext(ctx).
		SetRetryBackoffInterval(100*time.Millisecond, 10*time.Second).
		SetRetryHook(func(resp *req.Response, err error) {
			switch {
			case err != nil:
				log.Error(errors.Wrapf(err, "faied to exec quick node request %v", resp.Request.URL.String()))
			case resp.GetStatusCode() >= http.StatusBadRequest:
				log.Error(errors.Errorf("quick node request failed %v: %v, body: %v", resp.Request.URL.String(), resp.GetStatusCode(), resp.String()))
			}
		}).
		SetRetryCount(5).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			if err != nil {
				return true
			}

			return isRetryableStatusCode(resp.GetStatusCode())
		}).
		SetHeader("x-api-key", q.config.QuickNode.APIKey)
}

func isRetryableStatusCode(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (q *client) CreateStream(ctx context.Context, streamName, contractAddrToMonitor string) (*Stream, error) {
	filter, err := q.bondingCurveSmartContractFilterFunc(contractAddrToMonitor)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load filter function")
	}
	var startRange *uint // For bonded tokens, startRange = nil means "start from current block"
	if strings.EqualFold(contractAddrToMonitor, q.config.BondingCurveContract) {
		val := q.config.QuickNode.StartBlock
		startRange = &val
	}

	sslmode := "disable"
	if strings.Contains(q.config.QuickNode.StreamDestinationURL, "sslmode=require") {
		sslmode = "require"
	}
	params := &createStreamReq{
		Name:                  streamName,
		Network:               q.network,
		Dataset:               "block_with_receipts",
		FilterFunction:        base64.StdEncoding.EncodeToString(filter),
		Region:                q.config.QuickNode.Region,
		StartRange:            startRange,
		DatasetBatchSize:      1,
		IncludeStreamMetadata: "body",
		Destination:           "postgres",
		FixBlockReorgs:        0,
		KeepDistanceFromTip:   0,
		ElasticBatchEnabled:   true,
		DestinationAttributes: struct {
			Username         string `json:"username"`
			Password         string `json:"password"`
			Host             string `json:"host"`
			Port             uint16 `json:"port"`
			TableName        string `json:"table_name"`
			Database         string `json:"database"`
			MaxRetry         int    `json:"max_retry"`
			RetryIntervalSec int    `json:"retry_interval_sec"`
			SslMode          string `json:"sslmode"`
		}{
			Username:         q.streamDestination.User,
			Password:         q.streamDestination.Password,
			Host:             q.streamDestination.Host,
			Port:             q.streamDestination.Port,
			TableName:        "smart_contract_transactions",
			Database:         q.streamDestination.Database,
			SslMode:          sslmode,
			MaxRetry:         5,
			RetryIntervalSec: 5,
		},
		Status: "active",
	}
	var resp *req.Response
	if resp, err = q.req(ctx).SetBody(params).Post("/streams/rest/v1/streams"); err != nil {
		return nil, errors.Wrapf(err, "failed to post /streams/rest/v1/streams")
	} else if resp.GetStatusCode() >= http.StatusBadRequest {
		return nil, errors.Errorf("failed /streams/rest/v1/streams with %v: %v", resp.GetStatusCode(), resp.String())
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, errors.Wrapf(err2, "failed to read body of /streams/rest/v1/streams")
	} else {
		var stream Stream
		if err = json.UnmarshalContext(ctx, data, &stream); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal into %#v, data: %v", stream, string(data))
		}
		return &stream, nil
	}
}

func (q *client) bondingCurveSmartContractFilterFunc(contractAddrToMonitor string) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	err := q.bondingCurveSmartContractFilterTemplate.Execute(buf, struct {
		ContractAddress string
	}{
		ContractAddress: contractAddrToMonitor,
	})
	return buf.Bytes(), errors.Wrapf(err, "failed to format filter function")
}
