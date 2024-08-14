// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"net/http"
	"net/http/httputil"
	stdlibtime "time"

	"github.com/ice-blockchain/wintr/time"
)

type (
	DfnsClient interface {
		//ClientCall(ctx context.Context, method, url string, headers http.Header, jsonData []byte) (int, []byte, http.Header, error)
		ProxyCall(ctx context.Context, rw http.ResponseWriter, r *http.Request)
		StartDelegatedRecovery(ctx context.Context, username string, credentialId string) (*StartedDelegatedRecovery, error)
		StartDelegatedRegistration(ctx context.Context, username, kind string) (*StartedDelegatedRegistration, error)
		GetUser(ctx context.Context, userID string) (*User, error)
		VerifyWebhookSecret(fromWebhook string) bool
	}
	StartedDelegatedRecovery struct {
		Rp struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		TemporaryAuthenticationToken string `json:"temporaryAuthenticationToken"`
		SupportedCredentialKinds     struct {
			FirstFactor  []string `json:"firstFactor"`
			SecondFactor []string `json:"secondFactor"`
		} `json:"supportedCredentialKinds"`
		Challenge       string `json:"challenge"`
		PubKeyCredParam []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		} `json:"pubKeyCredParams"`
		Attestation        string `json:"attestation"`
		ExcludeCredentials []struct {
			Type       string `json:"type"`
			Id         string `json:"id"`
			Transports string `json:"transports"`
		} `json:"excludeCredentials"`
		AuthenticatorSelection struct {
			AuthenticatorAttachment string `json:"authenticatorAttachment"`
			ResidentKey             string `json:"residentKey"`
			RequireResidentKey      bool   `json:"requireResidentKey"`
			UserVerification        string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		AllowedRecoveryCredentials []struct {
			Id                   string `json:"id"`
			EncryptedRecoveryKey string `json:"encryptedRecoveryKey"`
		} `json:"allowedRecoveryCredentials"`
		OTPUrl string `json:"otpUrl"`
	}
	StartedDelegatedRegistration struct {
		Rp struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		TemporaryAuthenticationToken string `json:"temporaryAuthenticationToken"`
		SupportedCredentialKinds     struct {
			FirstFactor  []string `json:"firstFactor"`
			SecondFactor []string `json:"secondFactor"`
		} `json:"supportedCredentialKinds"`
		Challenge       string `json:"challenge"`
		PubKeyCredParam []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		} `json:"pubKeyCredParams"`
		Attestation        string `json:"attestation"`
		ExcludeCredentials []struct {
			Type       string `json:"type"`
			Id         string `json:"id"`
			Transports string `json:"transports"`
		} `json:"excludeCredentials"`
		AuthenticatorSelection struct {
			AuthenticatorAttachment string `json:"authenticatorAttachment"`
			ResidentKey             string `json:"residentKey"`
			RequireResidentKey      bool   `json:"requireResidentKey"`
			UserVerification        string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		OTPUrl string `json:"otpUrl"`
	}
	User struct {
		Username              string                 `json:"username"`
		UserID                string                 `json:"userId"`
		Kind                  string                 `json:"kind"`
		CredentialUuid        string                 `json:"credentialUuid"`
		OrgID                 string                 `json:"orgId"`
		Permissions           []Permission           `json:"permissions"`
		Scopes                []string               `json:"scopes"`
		IsActive              bool                   `json:"isActive"`
		IsServiceAccount      bool                   `json:"isServiceAccount"`
		IsRegistered          bool                   `json:"isRegistered"`
		PermissionAssignments []PermissionAssignment `json:"permissionAssignments"`
	}
	PermissionAssignment struct {
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
)

type (
	dfnsClient struct {
		serviceAccountClient *http.Client
		userClient           *http.Client

		serviceAccountProxy *httputil.ReverseProxy
		userProxy           *httputil.ReverseProxy
		webhookSecret       string
		cfg                 *config
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
