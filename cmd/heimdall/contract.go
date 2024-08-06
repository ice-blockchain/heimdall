// SPDX-License-Identifier: ice License 1.0

package main

import (
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
)

type (
	DfnsProxyData             map[string]any
	StartDelegatedRecoveryReq struct {
		Username               string                     `json:"username"`
		CredentialID           string                     `json:"credentialId"`
		TwoFAVerificationCodes map[TwoFAOptionEnum]string `json:"2FAVerificationCodes"`
		AppID                  string                     `header:"X-DFNS-APPID" swaggerignore:"true"`
	}
	TwoFAOptionEnum            = accounts.TwoFAOptionEnum
	StartDelegatedRecoveryResp struct {
		*accounts.StartedDelegatedRecovery
	}
	GetUserReq struct {
		UserID        string `uri:"userId" required:"true" swaggerignore:"true"`
		Authorization string `header:"Authorization" swaggerignore:"true"`
		AppID         string `header:"X-DFNS-APPID" swaggerignore:"true"`
	}
	User struct {
		*accounts.User
	}
	RelaysReq struct {
		UserID       string   `uri:"userId" required:"true" swaggerignore:"true"`
		FolloweeList []string `json:"followeeList"`
	}
	Relays struct {
		IONConnectRelays []string `json:"ionConnectRelays"`
	}
	IndexersReq struct {
		UserID string `uri:"userId" required:"true" swaggerignore:"true"`
	}
	Indexers struct {
		IONConnectIndexers []string `json:"ionConnectIndexers"`
	}
	Send2FARequestReq struct {
		UserID      string          `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption TwoFAOptionEnum `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Language    string          `header:"X-Language" swaggerignore:"true"`
		Email       *string         `json:"email,omitempty"`
		PhoneNumber *string         `json:"phoneNumber,omitempty"`
	}
	Send2FARequestResp struct {
		TOTPAuthentificatorURL *string `json:"TOTPAuthentificatorURL,omitempty"`
	}
	Verify2FARequestReq struct {
		UserID      string          `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption TwoFAOptionEnum `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Code        string          `form:"code" required:"true" swaggerignore:"true"`
	}
	Verify2FARequestResp struct {
	}
	WebhookData struct {
		ID   string         `json:"id"`
		Kind string         `json:"kind"`
		Date *time.Time     `json:"date"`
		Data map[string]any `json:"data"`
	}
	WebhookResp struct{}
)

const (
	applicationYamlKey         = "cmd/heimdall"
	proxyTimeout               = 30 * time.Second
	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
	twoFAAlreadySetupErrorCode = "2FA_ALREADY_SETUP"
	twoFANoPendingCode         = "NO_PENDING_2FA"
	twoFAInvalidCode           = "2FA_INVALID_CODE"
	twoFAExpiredCode           = "2FA_EXPIRED_CODE"
	twoFARequired              = "2FA_REQUIRED"
)

type (
	service struct {
		accounts accounts.Accounts
		cfg      *config
	}
	config struct {
		Host               string          `yaml:"host"`
		Version            string          `yaml:"version"`
		ProxyDfnsEndpoints []*dfnsEndpoint `yaml:"proxyDfnsEndpoints"`
	}
	dfnsEndpoint struct {
		Endpoint string `yaml:"endpoint"`
		Method   string `yaml:"method"`
		Tag      string `yaml:"tag"`
	}
)
