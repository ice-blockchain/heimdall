// SPDX-License-Identifier: ice License 1.0

package quicknode

import (
	"bytes"
	"context"
	"encoding/base64"
	"math"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"
	"github.com/jackc/pgx/v5/pgxpool"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

const (
	networkMainnet = "bnbchain-mainnet"
	networkTestnet = "bnbchain-testnet"
)

const (
	reqRetryCountMax = 20
	reqRetryWaitMin  = 100 * time.Millisecond
	reqRetryWaitMax  = 15 * time.Second

	apiHealthCheckInterval = 1 * time.Minute
)

func NewClient(ctx context.Context, applicationYamlKey string) Client {
	var cfg config

	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.QuickNode.APIKey == "" || cfg.QuickNode.APIKey == "-" {
		log.Warn("Using QUICKNODE_API_KEY from environment variable as api key is not set in config")
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
		bondingCurveSmartContractFilterTemplate: template.Must(template.New("bondingCurveSmartContractFilterTemplate").Parse(bondingCurveSmartContractFilterTemplate)),
		httpClient:                              req.C().SetBaseURL("https://api.quicknode.com/"),
		config:                                  &cfg,
		streamDestination:                       conf.ConnConfig,
		network:                                 network,
	}
	q.apiAlive.Store(true)

	if err = q.doHealthCheck(ctx); err != nil {
		log.Panic(errors.Wrapf(err, "failed to connect to QuickNode API"))
	}
	go q.HealthCheckThread(ctx, apiHealthCheckInterval)

	return q
}

func (q *client) HealthCheckThread(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for ctx.Err() == nil {
		select {
		case <-ticker.C:
			if err := q.doHealthCheck(ctx); err != nil {
				q.apiAlive.Store(false)
				log.Error(errors.Wrapf(err, "health check failed"))
			} else {
				q.apiAlive.Store(true)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (q *client) CurrentBlockRange() (startBlock, endBlock uint64) {
	startBlock, endBlock = q.config.QuickNode.StartBlock, math.MaxUint64
	if x := q.config.QuickNode.EndBlock; x != nil {
		endBlock = uint64(*x)
	}
	return startBlock, endBlock
}

func (q *client) doHealthCheck(ctx context.Context) error {
	resp, err := q.req(ctx).Get("/streams/rest/v1/streams")
	if err != nil {
		return errors.Wrapf(err, "failed to get /streams/rest/v1/streams")
	}

	switch resp.GetStatusCode() {
	case http.StatusOK:

	case http.StatusTooManyRequests:
		// Should not happen, but log it just in case.
		log.Warn("quicknode stream api rate limited")

	default:
		return errors.Errorf("quicknode stream api unavailable, status code: %v", resp.GetStatusCode())
	}
	return nil
}

func (q *client) HealthCheck(ctx context.Context) error {
	if q.apiAlive.Load() {
		return nil
	}
	return errApiDown
}

func (q *client) req(ctx context.Context) *req.Request {
	return q.httpClient.R().
		SetContext(ctx).
		SetRetryBackoffInterval(reqRetryWaitMin, reqRetryWaitMax).
		SetRetryHook(func(resp *req.Response, err error) {
			switch {
			case err != nil:
				log.Error(errors.Wrapf(err, "faied to exec quick node request %v", resp.Request.URL.String()))
			case resp.GetStatusCode() >= http.StatusBadRequest:
				log.Error(errors.Errorf("quick node request failed %v: %v, body: %v", resp.Request.URL.String(), resp.GetStatusCode(), resp.String()))
			}
		}).
		SetRetryCount(reqRetryCountMax).
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
	var startRange *uint64 // For bonded tokens, startRange = nil means "start from current block"
	if strings.EqualFold(contractAddrToMonitor, bondingcurve.ABIJSON) {
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
		Region:                "usa_east",
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
