// SPDX-License-Identifier: ice License 1.0

package main

import (
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
)

type (
	StartDelegatedRecoveryReq struct {
		Username               string                     `json:"username" allowUnauthorized:"true"`
		CredentialID           string                     `json:"credentialId" required:"true"`
		ClientID               string                     `header:"X-Client-ID" required:"true" swaggerignore:"true"`
		TwoFAVerificationCodes map[TwoFAOptionEnum]string `json:"2FAVerificationCodes"`
	}
	TwoFAOptionEnum            = accounts.TwoFAOptionEnum
	StartDelegatedRecoveryResp = accounts.StartedDelegatedRecovery
	GetUserReq                 struct {
		UserID        string `uri:"userId" required:"true" swaggerignore:"true"`
		Authorization string `header:"Authorization" swaggerignore:"true"`
		ClientID      string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
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
		UserID                 string                     `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption            TwoFAOptionEnum            `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Language               string                     `header:"X-Language" swaggerignore:"true"`
		Email                  *string                    `json:"email,omitempty"`
		PhoneNumber            *string                    `json:"phoneNumber,omitempty"`
		TwoFAVerificationCodes map[TwoFAOptionEnum]string `json:"2FAVerificationCodes"`
	}
	Delete2FAReq struct {
		UserID                      string          `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption                 TwoFAOptionEnum `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		TwoFAOptionValue            string          `uri:"twoFAOptionValue" required:"true" swaggerignore:"true"`
		TwoFAOptionVerificationCode string          `form:"twoFAOptionVerificationCode" required:"true"`
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
	RefreshTokenReq struct {
		Username string `json:"username"`
	}
	RefreshTokenResp struct {
		Token string `json:"token"`
	}
	WebhookData struct {
		ID   string         `json:"id" allowUnauthorized:"true"`
		Kind string         `json:"kind"`
		Date *time.Time     `json:"date"`
		Data map[string]any `json:"data"`
	}
	WebhookResp struct{}
)

const (
	applicationYamlKey         = "cmd/heimdall-identity-io"
	proxyTimeout               = 30 * time.Second
	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
	authentificatorReqNotMet   = "AUTHENTIFICATOR_REQ_NOT_MET"
	twoFANoPendingCode         = "NO_PENDING_2FA"
	twoFAInvalidCode           = "2FA_INVALID_CODE"
	userNotFound               = "USER_NOT_FOUND"
	twoFAExpiredCode           = "2FA_EXPIRED_CODE"
	twoFARequired              = "2FA_REQUIRED"
)

type (
	service struct {
		accounts accounts.Accounts
		cfg      *config
	}
	config struct {
		Host    string `yaml:"host"`
		Version string `yaml:"version"`
	}
)
