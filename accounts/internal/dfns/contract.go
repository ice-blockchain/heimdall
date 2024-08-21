// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	stdlibtime "time"

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
		//StartDelegatedRegistration(ctx context.Context, username, kind string) (*StartedDelegatedRegistration, error)
		GetUser(ctx context.Context, userID string) (*User, error)
		VerifyWebhookSecret(fromWebhook string) bool
	}
	StartedDelegatedRecovery map[string]any
	User                     map[string]any
	PermissionAssignment     struct {
		PermissionID string   `json:"permissionId"`
		AssignmentID string   `json:"assignmentId"`
		Name         string   `json:"permissionName"`
		Operations   []string `json:"operations"`
	}
	Permission struct {
		Id          string     `json:"id"`
		Name        string     `json:"name"`
		Operations  []string   `json:"operations"`
		Status      string     `json:"status"`
		IsImmutable bool       `json:"isImmutable"`
		DateCreated *time.Time `json:"dateCreated"`
		DateUpdated *time.Time `json:"dateUpdated"`
		IsArchived  bool       `json:"isArchived"`
	}
)

const (
	AuthHeaderCtxValue = "authHeaderCtxValue"
	AppIDCtxValue      = "XDfnsAppIDCtxValue"
	appIDHeader        = "x-dfns-appid"
	requestDeadline    = 25 * stdlibtime.Second
	jwksUrl            = "/.well-known/jwks.json"
)

var (
	ErrInvalidToken = errors.Errorf("invalid token")
	ErrExpiredToken = errors.Errorf("expired token")
)

var (
	cfg config
)

type (
	dfnsClient struct {
		serviceAccountClient *http.Client
		userClient           *http.Client

		serviceAccountProxy *httputil.ReverseProxy
		userProxy           *httputil.ReverseProxy
		webhookSecret       string
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
