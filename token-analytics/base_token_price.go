package tokenanalytics

import (
	"context"
	"net/http"
	"sync/atomic"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"

	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) startIONPriceSyncer(ctx context.Context) {
	ticker := stdlibtime.NewTicker(5 * stdlibtime.Second) //nolint:gosec,gomnd // Not an  issue.
	defer ticker.Stop()
	t.ionPrice = new(atomic.Pointer[float64])
	log.Panic(errors.Wrap(t.syncIONPrice(ctx), "failed to syncIONPrice"))

	for {
		select {
		case <-ticker.C:
			reqCtx, cancel := context.WithTimeout(ctx, 30*stdlibtime.Second)
			log.Error(errors.Wrap(t.syncIONPrice(reqCtx), "failed to syncIONPrice"))
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func (t *tokenAnalytics) syncIONPrice(ctx context.Context) error {
	stats, err := fetchIONPrice(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to fetchIONPrice")
	}
	t.ionPrice.Store(&stats.Price)

	return nil
}

func fetchIONPrice(ctx context.Context) (*ionPricingStats, error) {
	if resp, err := req.
		SetContext(ctx).
		SetRetryCount(25).
		SetRetryInterval(func(resp *req.Response, attempt int) stdlibtime.Duration {
			switch {
			case attempt <= 1:
				return 100 * stdlibtime.Millisecond
			case attempt == 2:
				return 1 * stdlibtime.Second
			default:
				return 5 * stdlibtime.Second
			}
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrap(err, "failed to fetch ion price, retrying..."))
			} else {
				body, bErr := resp.ToString()
				log.Error(errors.Wrapf(bErr, "failed to parse negative response body for fetching ion price"))
				log.Error(errors.Errorf("failed to fetch ion price with status code:%v, body:%v, retrying...", resp.GetStatusCode(), body))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() != http.StatusOK
		}).
		AddQueryParam("caller", "heimdall-token-analytics").
		SetHeader("Accept", "application/json").
		SetHeader("Cache-Control", "no-cache, no-store, must-revalidate").
		SetHeader("Pragma", "no-cache").
		SetHeader("Expires", "0").
		Get("https://data.ice.io/stats"); err != nil {
		return nil, errors.Wrap(err, "failed to fetch https://data.ice.io/stats")
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, errors.Wrap(err2, "failed to read body of https://data.ice.io/stats")
	} else {
		var stats ionPricingStats
		if err3 := json.Unmarshal(data, &stats); err3 != nil {
			return nil, errors.Wrapf(err3, "failed to unmarshal into %#v, data: `%v`", &stats, string(data))
		} else {
			return &stats, nil
		}
	}
}
