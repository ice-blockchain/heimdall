// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/imroc/req/v3"

	"github.com/ice-blockchain/subzero/server/http/events"
	"github.com/ice-blockchain/wintr/log"
)

func NewIonConnectClient() IonConnectClient {
	return &ionConnectClient{}
}

func (c *ionConnectClient) GetPost(ctx context.Context, relayUrl, eventAddress string) (*events.PostPreview, error) {
	preview, err := relayRequest[events.PostPreview](ctx, relayUrl, fmt.Sprintf("/v1/preview/%s", eventAddress))
	return preview, errors.Wrapf(err, "failed to get post preview from relay %v for event %v", relayUrl, eventAddress)
}

func relayRequest[T any](ctx context.Context, relayUrl, relativeUrl string, accept ...string) (*T, error) {
	acceptHeader := "application/json"
	if len(accept) > 0 && accept[0] != "" {
		acceptHeader = accept[0]
	}
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
	client := req.C().SetBaseURL(u.String()).EnableInsecureSkipVerify()
	if resp, err := client.R().
		SetContext(ctx).
		SetRetryCount(3).
		SetRetryInterval(func(resp *req.Response, attempt int) stdlibtime.Duration {
			return 1 * stdlibtime.Second
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to call relay %v, retrying...", relayUrl))
			} else {
				log.Error(errors.Errorf("failed to call relay %v (%v) with status code:%v, retrying...", relayUrl, relativeUrl, resp.GetStatusCode()))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || (resp.GetStatusCode() != http.StatusOK && resp.GetStatusCode() != http.StatusNotFound)
		}).
		SetHeader("Accept", acceptHeader).
		Get(relativeUrl); err != nil {
		return nil, errors.Wrapf(err, "failed to call relay %v%v", relayUrl, relativeUrl)

	} else if statusCode := resp.GetStatusCode(); statusCode != http.StatusOK {
		if statusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, errors.Errorf("failed to call relay %v%v with status code:%v", relayUrl, relativeUrl, statusCode)
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, errors.Wrapf(err2, "failed to read body of relay %v%v response", relayUrl, relativeUrl)
	} else {
		var relayResponse T
		if err = json.Unmarshal(data, &relayResponse); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal data: %v", string(data))
		}
		return &relayResponse, nil
	}
}
