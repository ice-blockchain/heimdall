// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/imroc/req/v3"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
)

type (
	identityClient struct {
		baseURL string
		apiKey  string
		client  *req.Client
	}

	communityTokenAdaptorRequest struct {
		Platform string `json:"platform"`
		PostID   string `json:"postId"`
	}

	communityTokenAdaptorResponse struct {
		Address string `json:"address"`
	}
)

func newIdentityClient(baseURL, apiKey string) *identityClient {
	return &identityClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: req.C().
			SetCommonHeader("Accept", "application/json").
			SetCommonHeader("X-API-Key", apiKey).
			SetTimeout(30 * time.Second),
	}
}

func (c *identityClient) AdaptExternalEventToIONConnectEvent(ctx context.Context, platform, postID string) (string, error) {
	reqBody := communityTokenAdaptorRequest{
		Platform: platform,
		PostID:   postID,
	}

	cCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var response communityTokenAdaptorResponse
	resp, err := c.client.R().
		SetContext(cCtx).
		SetRetryCount(5).
		SetRetryInterval(func(resp *req.Response, attempt int) time.Duration {
			switch {
			case attempt <= 1:
				return 100 * time.Millisecond
			case attempt == 2:
				return 1 * time.Second
			default:
				return 10 * time.Second
			}
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrap(err, "failed to create community token adaptor, retrying"))
			} else {
				log.Error(fmt.Errorf("failed to create community token adaptor with status %d, retrying", resp.GetStatusCode()))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() >= http.StatusInternalServerError
		}).
		SetHeader("Cache-Control", "no-cache, no-store, must-revalidate").
		SetHeader("Pragma", "no-cache").
		SetHeader("Expires", "0").
		SetBody(reqBody).
		SetSuccessResult(&response).
		Post(fmt.Sprintf("%s/v1/community-tokens/adaptors", c.baseURL))

	if err != nil {
		return "", errors.Wrap(err, "failed to send request to identity service")
	}

	if resp.GetStatusCode() != http.StatusCreated {
		return "", errors.Errorf("identity service returned status %d: %s", resp.GetStatusCode(), resp.String())
	}

	return response.Address, nil
}
