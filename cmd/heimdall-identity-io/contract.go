// SPDX-License-Identifier: ice License 1.0

package main

import (
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
)

type (
	AppAssociationReq struct {
		_ struct{} `json:"-" allowUnauthorized:"true"`
	}
	StartDelegatedRecoveryReq struct {
		TwoFAVerificationCodes map[TwoFAOptionEnum]string `json:"2FAVerificationCodes"`
		Username               string                     `json:"username" allowUnauthorized:"true"`
		CredentialID           string                     `json:"credentialId" required:"true"`
		ClientID               string                     `header:"X-Client-ID" required:"true" swaggerignore:"true"`
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
		Email                  *string                    `json:"email,omitempty"`
		PhoneNumber            *string                    `json:"phoneNumber,omitempty"`
		TwoFAVerificationCodes map[TwoFAOptionEnum]string `json:"2FAVerificationCodes"`
		UserID                 string                     `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption            TwoFAOptionEnum            `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Language               string                     `header:"X-Language" swaggerignore:"true"`
		UserSignature          string                     `header:"X-Useraction" swaggerignore:"true"`
	}
	Delete2FAReq struct {
		UserSignature                string            `header:"X-Useraction" swaggerignore:"true"`
		UserID                       string            `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption                  TwoFAOptionEnum   `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		TwoFAOptionValue             string            `uri:"twoFAOptionValue" required:"true" swaggerignore:"true"`
		TwoFAOptionVerificationCode  []string          `form:"twoFAOptionVerificationCode" required:"true"`
		TwoFAOptionVerificationValue []TwoFAOptionEnum `form:"twoFAOptionVerificationValue" required:"true"`
	}
	Send2FARequestResp struct {
		TOTPAuthenticatorURL *string `json:"TOTPAuthenticatorURL,omitempty"`
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
		Date *time.Time     `json:"date"`
		Data map[string]any `json:"data"`
		ID   string         `json:"id" allowUnauthorized:"true"`
		Kind string         `json:"kind"`
	}
	WebhookResp struct{}
)

const (
	applicationYamlKey         = "cmd/heimdall-identity-io"
	proxyTimeout               = 30 * time.Second
	userSignatureCtxValueKey   = "userSignatureCtxValueKey"
	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
	authenticatorReqNotMet     = "AUTHENTICATOR_REQ_NOT_MET"
	twoFANoPendingCode         = "NO_PENDING_2FA"
	twoFAInvalidCode           = "2FA_INVALID_CODE"
	userNotFound               = "USER_NOT_FOUND"
	twoFAExpiredCode           = "2FA_EXPIRED_CODE"
	twoFARequired              = "2FA_REQUIRED"
	invalidFollowees           = "INVALID_FOLLOWEES"
	invalidUserSignature       = "INVALID_SIGNATURE"
)

type (
	service struct {
		accounts accounts.Accounts
		cfg      *config
	}
	config struct {
		Host                    string `yaml:"host"`
		Version                 string `yaml:"version"`
		AppleAppSiteAssociation string `yaml:"appleAppSiteAssociation"`
		AssetLinks              string `yaml:"assetLinks"`
	}
)
