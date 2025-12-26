// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"net/http"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) startIONPriceSyncer(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second) //nolint:gosec,gomnd // Not an  issue.
	defer ticker.Stop()
	if err := t.syncIONPrice(ctx); err != nil {
		if !errors.Is(err, context.Canceled) && !storage.IsErr(err, storage.ErrReadOnly) {
			log.Panic(errors.Wrap(err, "failed to syncIONPrice"))
		}
	}

	for {
		select {
		case <-ticker.C:
			reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := t.syncIONPrice(reqCtx)
			if err != nil {
				if storage.IsErr(err, storage.ErrReadOnly) {
					cancel()
					log.Info("stopping ION price syncer. database is in read-only mode")

					return
				}
				log.Error(errors.Wrap(err, "failed to syncIONPrice"))
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func (t *tokenAnalytics) startBNBPriceLoader(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second) //nolint:gosec,gomnd // Not an  issue.
	defer ticker.Stop()
	if err := t.loadBNBPrice(ctx); err != nil {
		if !errors.Is(err, context.Canceled) && !storage.IsErr(err, storage.ErrReadOnly) {
			log.Panic(errors.Wrap(err, "failed to load bnb price from db"))
		}
	}

	for {
		select {
		case <-ticker.C:
			reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := t.loadBNBPrice(reqCtx)
			if err != nil {
				if storage.IsErr(err, storage.ErrReadOnly) {
					cancel()
					log.Info("stopping BNB price loader. database is in read-only mode")

					return
				}
				log.Error(errors.Wrap(err, "failed to loadBNBPrice"))
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func (t *tokenAnalyticsUsers) UpdateBNBPrice(ctx context.Context, price float64) error {
	return errors.Wrapf(saveBaseTokenPriceToDatabase(ctx, t.ingestedDataDB, "BNB", "BNB", price), "failed to save BNB price to database")
}

func (t *tokenAnalytics) loadBNBPrice(ctx context.Context) error {
	price, err := storage.Get[float64](ctx, t.ingestedDataDB, `SELECT price_usd FROM base_token_prices WHERE token_address = $1`, "BNB")
	if err != nil {
		return errors.Wrap(err, "failed to load BNB price from db")
	}

	t.bnbPriceUSD.Store(price)
	return nil
}

func (t *tokenAnalytics) syncIONPrice(ctx context.Context) error {
	stats, err := fetchIONPrice(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to fetchIONPrice")
	}
	t.ionPriceUSD.Store(&stats.Price)

	return errors.Wrapf(saveBaseTokenPriceToDatabase(ctx, t.ingestedDataDB, "ION", t.cfg.IONTokenAddress, stats.Price), "failed to save ION price to database")
}

func saveBaseTokenPriceToDatabase(ctx context.Context, db *storage.DB, symbol, tokenAddress string, price float64) (err error) {
	_, err = storage.Exec(ctx, db, `
		WITH old_price AS (
			SELECT price_usd
			FROM base_token_prices
			WHERE token_address = $1
		),
		updated AS (
			INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (token_address) DO UPDATE SET
				price_usd = EXCLUDED.price_usd,
				updated_at = EXCLUDED.updated_at,
				token_symbol = EXCLUDED.token_symbol
			RETURNING price_usd
		)
		INSERT INTO base_token_price_history (token_address, price_usd, created_at)
		SELECT $1, $3, NOW()
		WHERE NOT EXISTS (SELECT 1 FROM old_price)
		   OR (SELECT price_usd FROM old_price) != $3
	`, tokenAddress, symbol, price)

	if err != nil {
		return errors.Wrapf(err, "failed to save %v price to database", symbol)
	}
	return nil
}

func fetchIONPrice(ctx context.Context) (*ionPricingStats, error) {
	if resp, err := req.
		SetContext(ctx).
		SetRetryCount(25).
		SetRetryInterval(func(resp *req.Response, attempt int) time.Duration {
			switch {
			case attempt <= 1:
				return 100 * time.Millisecond
			case attempt == 2:
				return 1 * time.Second
			default:
				return 5 * time.Second
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
