// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"net/http"
	"net/http/httputil"

	"github.com/ice-blockchain/wintr/time"
)

type (
	DfnsClient interface {
		ClientCall(ctx context.Context, method, url string, headers http.Header, jsonData []byte) (int, []byte, http.Header, error)
		ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request)
	}
)

type (
	dfnsClient struct {
		serviceAccountClient *http.Client
		userClient           *http.Client

		serviceAccountProxy *httputil.ReverseProxy
		userProxy           *httputil.ReverseProxy

		cfg *config
	}
	config struct {
		DFNS struct {
			ServiceKey                 string `yaml:"serviceKey" mapstructure:"serviceKey"`
			ServiceAccountCredentialID string `yaml:"serviceAccountCredentialId" mapstructure:"serviceAccountCredentialId"`
			ServiceAccountPrivateKey   string `yaml:"serviceAccountPrivateKey" mapstructure:"serviceAccountPrivateKey"`
			AppID                      string `yaml:"appId" mapstructure:"appId"`
			BaseURL                    string `yaml:"baseUrl" mapstructure:"baseUrl"`
			WebhookURL                 string `yaml:"webhookUrl" mapstructure:"webhookUrl"`
		} `yaml:"dfns" mapstructure:"dfns"`
	}

	webhook struct {
		Id          string     `json:"id"`
		Url         string     `json:"url"`
		Events      []string   `json:"events"`
		Description string     `json:"description"`
		Status      string     `json:"status"`
		DateCreated *time.Time `json:"dateCreated"`
		DateUpdated *time.Time `json:"dateUpdated"`
		Secret      *string    `json:"secret"`
	}
	page[T any] struct {
		Items []T `json:"items"`
	}
)
