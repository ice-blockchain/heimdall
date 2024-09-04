// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
	stdlibtime "time"

	"github.com/dfns/dfns-sdk-go/credentials"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/time"
)

type (
	AuthClient interface {
		VerifyToken(ctx context.Context, token string) (server.Token, error)
	}
	DfnsClient interface {
		ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) (respBody io.Reader)
		StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*StartedDelegatedRecovery, error)
		GetUser(ctx context.Context, userID string) (*User, error)
		VerifyWebhookSecret(fromWebhook string) bool
	}
	StartedDelegatedRecovery map[string]any
	User                     map[string]any
)

const (
	AuthHeaderCtxValue = "authHeaderCtxValue"
	AppIDCtxValue      = "XDfnsAppIDCtxValue"
	appIDHeader        = "X-Dfns-Appid"
	clientIDHeader     = "X-Client-Id"
	requestDeadline    = 25 * stdlibtime.Second
	jwksUrl            = "/.well-known/jwks.json"
)

var (
	ErrInvalidToken = errors.Errorf("invalid token")
	ErrExpiredToken = errors.Errorf("expired token")
)

type (
	dfnsClient struct {
		cfg                   *config
		serviceAccountSigner  *credentials.AsymmetricKeySigner
		webhookSecret         string
		userClients           map[string]*http.Client
		serviceAccountClients map[string]*http.Client
		userMx                sync.Mutex
		serviceAccountMx      sync.Mutex
		proxies               map[string]*httputil.ReverseProxy
		proxyMx               sync.Mutex
	}
	config struct {
		DFNS dfnsCfg `yaml:"delegated_relying_party" mapstructure:"delegated_relying_party"`
	}
	dfnsCfg struct {
		ServiceKey                 string `yaml:"serviceKey" mapstructure:"serviceKey" json:"serviceKey"`
		ServiceAccountCredentialID string `yaml:"serviceAccountCredentialId" mapstructure:"serviceAccountCredentialId" json:"serviceAccountCredentialId"`
		ServiceAccountPrivateKey   string `yaml:"serviceAccountPrivateKey" mapstructure:"serviceAccountPrivateKey" json:"serviceAccountPrivateKey"`
		AppID                      string `yaml:"appId" mapstructure:"appId" json:"appId"`
		OrganizationID             string `yaml:"organizationId" mapstructure:"organizationId" json:"organizationId"`
		BaseURL                    string `yaml:"baseUrl" mapstructure:"baseUrl" json:"baseUrl"`
		WebhookURL                 string `yaml:"webhookUrl" mapstructure:"webhookUrl"`
		Auth                       struct {
			Issuer string `yaml:"issuer" mapstructure:"issuer"`
		} `yaml:"auth" mapstructure:"auth"`
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
	dfnsAuth struct {
		dfnsPubKeys *jwk.Cache
		cfg         *config
	}
	dfnsToken struct {
		userID   string
		username string
	}
	proxyResponseBody struct {
		http.ResponseWriter
		Body io.Writer
	}
)
