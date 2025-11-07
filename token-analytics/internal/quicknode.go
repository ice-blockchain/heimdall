package internal

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
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
	"github.com/imroc/req/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

func NewQuickNodeClient(ctx context.Context, applicationYamlKey string) QuickNodeClient {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.QuickNode.APIKey == "" || cfg.QuickNode.APIKey == "-" {
		cfg.QuickNode.APIKey = os.Getenv("QUICKNODE_API_KEY")
	}
	filterTempl := template.Must(template.New("quickNode-filter").Parse(filterTemplate))
	conf, err := pgxpool.ParseConfig(cfg.QuickNode.DestinationUrl)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to parse destination url"))
	}
	q := &quickNodeClient{
		filterTemplate: filterTempl,
		client:         req.C().SetBaseURL("https://api.quicknode.com/"),
		config:         &cfg,
		destination:    conf.ConnConfig,
	}
	if err = q.bootstrap(ctx); err != nil {
		log.Panic(errors.Wrapf(err, "failed to bootstrap quick node conn"))
	}
	return q
}

func (q *quickNodeClient) bootstrap(ctx context.Context) error {
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

func (q *quickNodeClient) req(ctx context.Context) *req.Request {
	return q.client.R().
		SetContext(ctx).
		SetRetryBackoffInterval(100*time.Millisecond, 10*time.Second).
		SetRetryHook(func(resp *req.Response, err error) {
			switch {
			case err != nil:
				log.Error(errors.Wrapf(err, "faied to exec quick node request %v %v", resp.Request.URL.String()))
			case resp.GetStatusCode() >= http.StatusBadRequest:
				log.Error(errors.Errorf("quick node request failed %v: %v", resp.Request.URL.String(), resp.GetStatusCode()))
			}
		}).
		SetRetryCount(5).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() >= http.StatusBadRequest
		}).
		SetHeader("x-api-key", q.config.QuickNode.APIKey)
}

func (q *quickNodeClient) CreateStream(ctx context.Context, streamName, contractAddrToMonitor string) (*Stream, error) {
	filter, err := q.filterFunc(contractAddrToMonitor)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load filter function")
	}
	sslmode := "disable"
	if strings.Contains(q.config.QuickNode.DestinationUrl, "sslmode=require") {
		sslmode = "require"
	}
	params := &createStreamReq{
		Name:                  streamName,
		Network:               q.config.QuickNode.Network,
		Dataset:               "block_with_receipts",
		FilterFunction:        base64.StdEncoding.EncodeToString([]byte(filter)),
		Region:                "usa_east",
		StartRange:            q.config.QuickNode.StartBlock,
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
			Username:         q.destination.User,
			Password:         q.destination.Password,
			Host:             q.destination.Host,
			Port:             q.destination.Port,
			TableName:        "incoming_data",
			Database:         q.destination.Database,
			SslMode:          sslmode,
			MaxRetry:         5,
			RetryIntervalSec: 5,
		},
		Status: "active",
	}
	// TODO: For now there are only a few events in blocks 9553982-9553986, remove once we have more events
	if q.config.QuickNode.Network == "ethereum-sepolia" && q.config.QuickNode.StartBlock == 9553982 {
		endBlock := uint(9553986)
		params.EndRange = &endBlock
	}
	var resp *req.Response
	if resp, err = q.req(ctx).SetBody(params).Post("/streams/rest/v1/streams"); err != nil {
		return nil, errors.Wrapf(err, "failed to post /streams/rest/v1/streams")
	} else if resp.GetStatusCode() >= http.StatusBadRequest {
		return nil, errors.Errorf("failed /streams/rest/v1/streams with %v: %v", resp.GetStatusCode(), string(resp.String()))
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

func (q *quickNodeClient) filterFunc(contractAddrToMonitor string) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	err := q.filterTemplate.Execute(buf, struct {
		ContractAddress string
	}{
		ContractAddress: contractAddrToMonitor,
	})
	return buf.Bytes(), errors.Wrapf(err, "failed to format filter function")
}
