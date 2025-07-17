// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	stdlibtime "time"

	"github.com/alitto/pond/v2"
	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"

	"github.com/ice-blockchain/subzero/server/http/nip11"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func init() {
	req.DefaultClient().GetClient().Transport = &http2.Transport{}
	req.DefaultClient().GetClient().Timeout = 30 * stdlibtime.Second
	req.DefaultClient().SetJsonMarshal(json.Marshal)
	req.DefaultClient().SetJsonUnmarshal(json.Unmarshal)
}

func NewRelaysSync(ctx context.Context) RelaysSyncer {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	r := relaysSyncer{
		db:       db,
		shutdown: db.Close,
	}
	return &r
}

func (r *relaysSyncer) getAllRelays(ctx context.Context) ([]string, error) {
	allRelays, err := storage.Select[struct {
		IONConnectRelays []string `db:"ion_connect_relays"`
	}](ctx, r.db, `SELECT array_agg(url) as ion_connect_relays FROM ion_connect_relays;`)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			err = nil
		}
		return nil, errors.Wrapf(err, "failed to get all ion connect relays from db")
	}
	if len(allRelays) == 0 {
		return nil, ErrNoRelays
	}
	return allRelays[0].IONConnectRelays, nil
}

func (r *relaysSyncer) CheckRelayStatus(ctx context.Context) error {
	urls, err := r.getAllRelays(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to check relays status, failed to read from relay list from db")
	}
	workerPool := pond.NewResultPool[nip11Result](len(urls))
	group := workerPool.NewGroup()
	for _, relayUrl := range urls {
		group.Submit(func() nip11Result {
			reqCtx, reqCancel := context.WithTimeout(ctx, 30*stdlibtime.Second)
			defer reqCancel()
			res, err := r.requestNIP11(reqCtx, relayUrl)
			return nip11Result{url: relayUrl, nip11: res, err: err}
		})
	}
	results, err := group.Wait()
	if err != nil {
		return errors.Wrapf(err, "failed to sync relays")
	}
	return errors.Wrapf(r.updateRelaysStatus(ctx, results), "failed to update relays status %+v", results)
}

func (r *relaysSyncer) updateRelaysStatus(ctx context.Context, results []nip11Result) error {
	now := time.Now()
	placeholders, params := r.buildBatchUpdate(now, results)
	if len(placeholders) == 0 {
		return nil
	}
	sql := fmt.Sprintf(`	
			UPDATE ion_connect_relays SET
				updated_at = $1::TIMESTAMP, 
				unhealthy_started_at = CASE WHEN (update_data.unhealthy_started_at IS NOT NULL AND ion_connect_relays.unhealthy_started_at IS NULL) OR (update_data.unhealthy_started_at IS NULL AND ion_connect_relays.unhealthy_started_at IS NOT NULL) THEN update_data.unhealthy_started_at ELSE ion_connect_relays.unhealthy_started_at END,
				total_used_storage = CASE WHEN (update_data.unhealthy_started_at IS NULL) THEN update_data.total_used_storage ELSE ion_connect_relays.total_used_storage END,
				nip_11 = CASE WHEN (update_data.unhealthy_started_at IS NULL) THEN update_data.nip_11 ELSE ion_connect_relays.nip_11 END
			FROM (
				VALUES %[1]v
			) as update_data (
				url, total_used_storage, unhealthy_started_at, nip_11
			)
			WHERE ion_connect_relays.url = update_data.url;`, placeholders)
	return errors.Wrapf(storage.DoInTransaction(ctx, r.db, func(conn storage.QueryExecer) error {
		if rows, err := storage.Exec(ctx, conn, sql, params...); err != nil {
			return errors.Wrapf(err, "failed to update relays state after syncing NIP-11")
		} else if rows != uint64(len(results)) {
			return errors.Errorf("unexpected updated relays count after syncing NIP-11: extected %v got %v", len(results), rows)
		}
		if _, refreshErr := storage.Exec(ctx, conn, "REFRESH materialized view ion_connect_relays_with_the_lowest_storage_by_region;"); refreshErr != nil {
			return errors.Wrapf(refreshErr, "failed to refresh relays by region syncing NIP-11")
		}
		return nil
	}), "failed to update relays state after syncing NIP-11")
}

func (s *relaysSyncer) buildBatchUpdate(now *time.Time, results []nip11Result) (sql string, params []any) {
	placeholders := make([]string, 0, len(results))
	idx := 2
	params = make([]any, 0, 1+len(results)*3)
	params = append(params, now.Time)
	for _, nip11 := range results {
		if nip11.err != nil {
			params = append(params, nip11.url, 0, nil)
			placeholders = append(placeholders, fmt.Sprintf("($%[1]v, $%[2]v::BIGINT,$1::TIMESTAMP, $%[3]v::JSONB)", idx, idx+1, idx+2))
		} else {
			params = append(params, nip11.url, nip11.nip11.SystemMetrics.UsedTotalStorage, nip11.nip11)
			placeholders = append(placeholders, fmt.Sprintf("($%[1]v, $%[2]v::BIGINT, null::TIMESTAMP, $%[3]v::JSONB)", idx, idx+1, idx+2))
		}
		idx += 3
	}
	return strings.Join(placeholders, ", \n"), params
}

func (r *relaysSyncer) requestNIP11(ctx context.Context, relayUrl string) (*nip11.RelayInformationDocument, error) {
	u, err := url.Parse(relayUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid url: %v", relayUrl)
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return nil, errors.Errorf("invalid scheme :%v", u.Scheme)
	}
	if resp, err := req.
		SetContext(ctx).
		SetRetryCount(3).
		SetRetryInterval(func(resp *req.Response, attempt int) stdlibtime.Duration {
			return 1 * stdlibtime.Second
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to call relay %v, retrying...", relayUrl))
			} else {
				log.Error(errors.Errorf("failed to call relay %v with status code:%v, retrying...", relayUrl, resp.GetStatusCode()))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() != http.StatusOK
		}).
		SetHeader("Accept", "application/nostr+json").
		Get(u.String()); err != nil {
		return nil, errors.Wrapf(err, "failed to call relay %v", relayUrl)

	} else if statusCode := resp.GetStatusCode(); statusCode != http.StatusOK {
		return nil, errors.Errorf("failed to check relay %v with status code:%v", relayUrl, statusCode)
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, errors.Wrapf(err2, "failed to read body of relay %v response", relayUrl)
	} else {
		var nip11 nip11.RelayInformationDocument
		if err = json.UnmarshalContext(ctx, data, &nip11); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal data: %v", string(data))
		}
		return &nip11, nil
	}
}
