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
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/time"
)

type (
	AuthClient interface {
		VerifyToken(ctx context.Context, token string) (server.Token, error)
	}
	DfnsClient interface {
		ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) (status int, respBody io.Reader)
		StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*StartedDelegatedRecovery, error)
		GetUser(ctx context.Context, userID string) (*User, error)
		VerifyWebhookSecret(fromWebhook string) bool
		RegisterPostProxyCallback(url string, cb func(ctx context.Context, now *time.Time, res map[string]any) error)
	}
	RefreshAuth interface {
		AuthClient
		IssueRefreshToken(ctx context.Context, now *time.Time, userID, username string) (string, error)
	}
	StartedDelegatedRecovery map[string]any
	User                     map[string]any
)

const (
	AuthHeaderCtxValue               = "authHeaderCtxValue"
	AppIDCtxValue                    = "XDfnsAppIDCtxValue"
	appIDHeader                      = "X-Dfns-Appid"
	userActionDfnsHeader             = "X-Dfns-Useraction"
	userActionHeader                 = "X-Useraction"
	clientIDHeader                   = "X-Client-Id"
	requestDeadline                  = 25 * stdlibtime.Second
	jwksUrl                          = "/.well-known/jwks.json"
	initLoginUrl                     = "/auth/login/init"
	completeLoginUrl                 = "/auth/login"
	initDelegatedRegistrationUrl     = "/auth/registration/delegated"
	completeDelegatedRegistrationUrl = "/auth/registration/enduser"
	delegatedLoginUrl                = "/auth/login/delegated" // Refresh token actually.

	DefaultWalletNetwork = "KeyEdDSA"
	DefaultWalletName    = "main"
)

var (
	ErrInvalidToken = server.ErrInvalidToken
	ErrExpiredToken = server.ErrExpiredToken
)

type (
	dfnsClient struct {
		refreshAuthIssuer       RefreshAuth
		cfg                     *config
		serviceAccountSigner    *credentials.AsymmetricKeySigner
		userClients             map[string]*http.Client
		serviceAccountClients   map[string]*http.Client
		proxies                 map[string]*httputil.ReverseProxy
		callbacks               map[string]func(ctx context.Context, now *time.Time, res map[string]any) error
		bodyModifiableCallbacks map[string]func(ctx context.Context, now *time.Time, res map[string]any, r *http.Response) error
		webhookSecret           string
		userMx                  sync.Mutex
		serviceAccountMx        sync.Mutex
		proxyMx                 sync.Mutex
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
		RefreshAuth struct {
			Issuer         string              `yaml:"issuer" mapstructure:"issuer"`
			Secret         string              `yaml:"secret" mapstructure:"secret"`
			ExpirationTime stdlibtime.Duration `yaml:"expirationTime" mapstructure:"expirationTime"`
		} `yaml:"refreshToken" mapstructure:"refreshToken"`
	}

	webhook struct {
		DateCreated *time.Time `json:"dateCreated"`
		DateUpdated *time.Time `json:"dateUpdated"`
		Secret      *string    `json:"secret"`
		Id          string     `json:"id"`
		Url         string     `json:"url"`
		Description string     `json:"description"`
		Status      string     `json:"status"`
		Events      []string   `json:"events"`
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
		Body   io.Writer
		Status int
	}
	refreshToken struct {
		*jwt.RegisteredClaims
		UserId   string `json:"userId"`
		UserName string `json:"username"`
	}
	refreshAuth struct {
		cfg       *config
		signToken func(token *jwt.Token) (string, error)
	}
)
