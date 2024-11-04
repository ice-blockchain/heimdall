// SPDX-License-Identifier: ice License 1.0

package main

import (
	"embed"
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
)

type (
	AppAssociationReq struct {
		_ struct{} `json:"-" allowUnauthorized:"true"`
	}
	StartDelegatedRecoveryReq struct {
		TwoFAVerificationCodes map[TwoFAOptionWithAddr]string `json:"2FAVerificationCodes"`
		Username               string                         `json:"username" allowUnauthorized:"true"`
		CredentialID           string                         `json:"credentialId" required:"true"`
		ClientID               string                         `header:"X-Client-ID" required:"true" swaggerignore:"true"`
	}
	TwoFAOptionEnum            = accounts.TwoFAOptionEnum
	TwoFAOptionWithAddr        = accounts.TwoFAOptionWithAddr
	StartDelegatedRecoveryResp = accounts.StartedDelegatedRecovery
	GetUserReq                 struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		Authorization     string `header:"Authorization" swaggerignore:"true"`
		ClientID          string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
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
	WalletViewReq struct {
		UserID string                     `uri:"userId" required:"true" swaggerignore:"true"`
		Name   string                     `json:"name" required:"true"`
		Items  []*accounts.WalletViewItem `json:"items" required:"true"`
	}
	GetWalletConfigurationReq struct {
		KnownVersion *int `form:"known_version" required:"false"`
	}
	WalletConfiguration struct {
		Version        int                       `json:"version"`
		AvailableCoins []*accounts.AvailableCoin `json:"availableCoins"`
	}
	WalletView        = accounts.WalletView
	WalletViews       = []*WalletView
	GetWalletViewsReq struct {
		UserID string `uri:"userId" required:"true" swaggerignore:"true"`
	}
	WalletViewReference struct {
		UserID         string `uri:"userId" required:"true" swaggerignore:"true"`
		WalletViewName string `uri:"walletViewName" required:"true" swaggerignore:"true"`
	}
	ModifyWalletViewReq struct {
		Bogus string `json:"bogus" uri:"bogus" swaggerignore:"true"` // It's just for the router to register the body binder.
		WalletViewReference
		WalletViewReq
	}
	Send2FARequestReq struct {
		Email                  *string                        `json:"email,omitempty"`
		PhoneNumber            *string                        `json:"phoneNumber,omitempty"`
		TwoFAVerificationCodes map[TwoFAOptionWithAddr]string `json:"2FAVerificationCodes"`
		UserID                 string                         `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption            TwoFAOptionEnum                `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Language               string                         `header:"X-Language" swaggerignore:"true"`
		UserSignature          string                         `header:"X-Useraction" swaggerignore:"true"`
	}
	Delete2FAReq struct {
		UserSignature                string          `header:"X-Useraction" swaggerignore:"true"`
		UserID                       string          `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption                  TwoFAOptionEnum `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		TwoFAOptionValue             string          `uri:"twoFAOptionValue" required:"true" swaggerignore:"true"`
		TwoFAOptionVerificationCode  []string        `form:"twoFAOptionVerificationCode" required:"true"`
		TwoFAOptionVerificationValue []string        `form:"twoFAOptionVerificationValue" required:"true"`
	}
	Send2FARequestResp struct {
		TOTPAuthenticatorURL *string `json:"TOTPAuthenticatorURL,omitempty"`
	}
	Verify2FARequestReq struct {
		UserID      string              `uri:"userId" required:"true" swaggerignore:"true"`
		TwoFAOption TwoFAOptionWithAddr `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Code        string              `form:"code" required:"true" swaggerignore:"true"`
	}
	Verify2FARequestResp struct {
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
	invalidUsername            = "INVALID_USERNAME"
	duplicate                  = "DUPLICATE"
	lastEntry                  = "LAST_ENTRY"
	notFound                   = "NOT_FOUND"
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

//go:embed templates/*.html
var templates embed.FS
