// SPDX-License-Identifier: ice License 1.0

package main

import (
	"embed"
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	hashtagstatistics "github.com/ice-blockchain/heimdall/hashtag-statistics"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/subzero/model"
)

type (
	Version           uint8
	Language          string
	AppAssociationReq struct {
		_ struct{} `json:"-" allowUnauthorized:"true"`
	}
	StartDelegatedRecoveryReq struct {
		TwoFAVerificationCodes map[TwoFAOptionWithAddr]string `json:"2FAVerificationCodes"`
		Username               string                         `json:"username" allowUnauthorized:"true"`
		CredentialID           string                         `json:"credentialId" required:"true"`
		ClientID               string                         `header:"X-Client-ID" required:"true" swaggerignore:"true"`
	}
	GetLoginChallenge struct {
		TwoFAVerificationCodes map[TwoFAOptionWithAddr]string `json:"2FAVerificationCodes"`
		Username               string                         `json:"username" allowUnauthorized:"true"`
		ClientID               string                         `header:"X-Client-ID" required:"true" swaggerignore:"true"`
	}
	LoginChallenge             = accounts.LoginChallenge
	TwoFAOptionEnum            = accounts.TwoFAOptionEnum
	TwoFAOptionWithAddr        = accounts.TwoFAOptionWithAddr
	StartDelegatedRecoveryResp = accounts.StartedDelegatedRecovery
	GetUserReq                 struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		Authorization     string `header:"Authorization" swaggerignore:"true" allowUnauthorized:"true"`
		ClientID          string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
	}
	DeleteUserReq struct {
		UserID        string `uri:"userId" required:"true" swaggerignore:"true"`
		Authorization string `header:"Authorization" swaggerignore:"true"`
		ClientID      string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
		UserSignature string `header:"X-Useraction" swaggerignore:"true"`
	}
	User struct {
		*accounts.User
	}
	RelaysReq struct {
		UserIDOrMasterKey string   `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		FolloweeList      []string `json:"followeeList"`
	}
	AllRelaysReq struct {
		IONConnectRelay string `form:"ion-connect-relay" required:"true"`
	}
	HashtagsEventsReq struct {
		Events []*model.Event `json:"events" binding:"required,min=1,dive" allowUnauthorized:"true"`
	}
	GetTopHashtagsReq struct {
		Authorization string `header:"Authorization" required:"true" swaggerignore:"true"`
		Keyword       string `form:"keyword" required:"false"`
		Limit         int    `form:"limit" required:"false"`
	}
	Relays struct {
		IONConnectRelays []string `json:"ionConnectRelays"`
	}
	IndexersReq struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
	}
	Indexers struct {
		IONConnectIndexers []string `json:"ionConnectIndexers"`
	}
	WalletViewReq struct {
		UserIDOrMasterKey string                  `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		Name              string                  `json:"name" required:"true"`
		Items             []*accounts.CoinMapping `json:"items" required:"true"`
		SymbolGroups      []string                `json:"symbolGroups" required:"true"`
	}
	APIKey struct {
		APIKey string `header:"X-API-Key" allowUnauthorized:"true"`
	}
	ImportCoinReq struct {
		Network         string `json:"network"`
		ContractAddress string `json:"contractAddress"`
	}
	Coin                 = coins.Coin
	Network              = coins.Network
	SymbolGroupWithCoins = coins.SymbolGroupWithCoins
	GetVersionedCoins    struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		Version           *int   `form:"version" required:"false"`
	}
	VersionedCoins struct {
		Version  uint64        `json:"version"`
		Coins    []*coins.Coin `json:"coins"`
		Networks []*Network    `json:"networks"`
	}
	SyncCoinsReq struct {
		SymbolGroup []string `form:"symbolGroup" required:"true"`
	}
	GetCoinsOfSymbolGroupReq struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		SymbolGroup       string `uri:"symbolGroup" required:"true" swaggerignore:"true"`
	}
	CoinWithWalletInfo = accounts.CoinWithWalletInfo
	WalletView         = accounts.WalletView
	WalletViews        = []*WalletView
	GetWalletViewsReq  struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
	}
	WalletViewReference struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		WalletViewID      string `uri:"walletViewId" required:"true" swaggerignore:"true"`
	}
	ModifyWalletViewReq struct {
		Bogus string `json:"bogus" uri:"bogus" swaggerignore:"true"` // It's just for the router to register the body binder.
		WalletViewReference
		WalletViewReq
	}
	CreateWalletReq struct {
		Network       string `json:"network" required:"true"`
		WalletViewID  string `json:"walletViewId" required:"true"`
		ClientID      string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
		UserAction    string `header:"X-Useraction" required:"true" swaggerignore:"true"`
		Authorization string `header:"Authorization" required:"true" swaggerignore:"true"`
	}
	Wallet    = accounts.Wallet
	GetConfig struct {
		Version    *Version `form:"version" allowUnauthorized:"true"`
		ConfigName string   `uri:"configName" allowUnauthorized:"true"`
	}
	Send2FARequestReq struct {
		Email                  *string                        `json:"email,omitempty"`
		PhoneNumber            *string                        `json:"phoneNumber,omitempty"`
		Replace                *string                        `json:"replace"`
		TwoFAVerificationCodes map[TwoFAOptionWithAddr]string `json:"2FAVerificationCodes"`
		UserIDOrMasterKey      string                         `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		TwoFAOption            TwoFAOptionEnum                `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Language               string                         `header:"X-Language" swaggerignore:"true"`
		UserSignature          string                         `header:"X-Useraction" swaggerignore:"true"`
		Authorization          string                         `header:"Authorization" swaggerignore:"true" allowUnauthorized:"true"`
	}
	Delete2FAReq struct {
		UserSignature                string          `header:"X-Useraction" swaggerignore:"true"`
		UserIDOrMasterKey            string          `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		TwoFAOption                  TwoFAOptionEnum `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		TwoFAOptionValue             string          `uri:"twoFAOptionValue" required:"true" swaggerignore:"true"`
		TwoFAOptionVerificationCode  []string        `form:"twoFAOptionVerificationCode" required:"true"`
		TwoFAOptionVerificationValue []string        `form:"twoFAOptionVerificationValue" required:"true"`
	}
	Send2FARequestResp struct {
		TOTPAuthenticatorURL *string `json:"TOTPAuthenticatorURL,omitempty"`
	}
	Verify2FARequestReq struct {
		UserIDOrMasterKey string              `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		TwoFAOption       TwoFAOptionWithAddr `uri:"twoFAOption" required:"true" swaggerignore:"true"`
		Code              string              `form:"code" required:"true" swaggerignore:"true"`
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
	GetNFTsReq  struct {
		WalletID string `uri:"walletId"`
	}
	NFTCollection struct {
		WalletID string       `json:"walletId"`
		Network  string       `json:"network"`
		NFTs     []*coins.NFT `json:"nfts"`
	}
	GetContentCreatorsReq struct {
		Authorization        string   `header:"Authorization" swaggerignore:"true"`
		Limit                uint64   `form:"limit" required:"true" swaggerignore:"true"`
		ExcludeMasterPubKeys []string `json:"excludeMasterPubKeys,omitempty"`
	}
	GetVerifiedBadgeReq struct {
		Authorization     string `header:"Authorization" swaggerignore:"true" allowUnauthorized:"true"`
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
	}
	VerifiedBadgeEvents struct {
		Events []*model.Event `json:"events"`
	}
	LiteUser = accounts.LiteUser
)

const (
	applicationYamlKey         = "cmd/heimdall-identity-io"
	proxyTimeout               = 30 * time.Second
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
	twoFANotConfigured         = "2FA_NOT_CONFIGURED"
	invalid2FAToTReplace       = "INVALID_2FA_REPLACE"
	wrongRelay                 = "WRONG_RELAY"

	configNameRequiredAndroidAppVersion = "required_android_app_version"
	configNameRequiredIOSAppVersion     = "required_ios_app_version"
	configNameRequiredMacOSAppVersion   = "required_macos_app_version"
	configNameRequiredWindowsAppVersion = "required_windows_app_version"
	configNameRequiredLinuxAppVersion   = "required_linux_app_version"
	configNameServicePubkeys            = "service_pubkeys"
)

type (
	service struct {
		accounts          accounts.Accounts
		coins             coins.Coins
		relays            relaymanagement.Relays
		hashtagStatistics hashtagstatistics.HashtagStatistics
		cfg               *config
	}
	config struct {
		Host                    string   `yaml:"host"`
		Version                 string   `yaml:"version"`
		APIKey                  []string `yaml:"api-key" mapstructure:"api-key"`
		AppleAppSiteAssociation string   `yaml:"appleAppSiteAssociation"`
		AssetLinks              string   `yaml:"assetLinks"`
		RequiredAppVersions     struct {
			Android string `yaml:"android" mapstructure:"android"`
			IOS     string `yaml:"ios" mapstructure:"ios"`
			MacOS   string `yaml:"macos" mapstructure:"macos"`
			Windows string `yaml:"windows" mapstructure:"windows"`
			Linux   string `yaml:"linux" mapstructure:"linux"`
		} `yaml:"requiredAppVersions" mapstructure:"requiredAppVersions"`
	}
)

var (
	//go:embed templates/*.html
	templates embed.FS
	//go:embed content-categories/*.json
	contentCategories embed.FS
	//go:embed translations/*/*.json
	translations        embed.FS
	allValidConfigNames = map[string]func(cfg *config) (any, Version){
		configNameRequiredAndroidAppVersion: func(cfg *config) (any, Version) { return cfg.RequiredAppVersions.Android, Version(0) },
		configNameRequiredIOSAppVersion:     func(cfg *config) (any, Version) { return cfg.RequiredAppVersions.IOS, Version(0) },
		configNameRequiredMacOSAppVersion:   func(cfg *config) (any, Version) { return cfg.RequiredAppVersions.MacOS, Version(0) },
		configNameRequiredWindowsAppVersion: func(cfg *config) (any, Version) { return cfg.RequiredAppVersions.Windows, Version(0) },
		configNameRequiredLinuxAppVersion:   func(cfg *config) (any, Version) { return cfg.RequiredAppVersions.Linux, Version(0) },
	}
)
