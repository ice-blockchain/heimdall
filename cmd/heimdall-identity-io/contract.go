// SPDX-License-Identifier: ice License 1.0

package main

import (
	"embed"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/heimdall/following"
	hashtagstatistics "github.com/ice-blockchain/heimdall/hashtag-statistics"
	nftcontent "github.com/ice-blockchain/heimdall/nft-content"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/subzero/validation"
)

type (
	Version           uint64
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
	LoginChallenge   = accounts.LoginChallenge
	InitRegistration struct {
		IdentityKeyName  string `json:"email" required:"true" allowUnauthorized:"true"`
		EarlyAccessEmail string `json:"earlyAccessEmail" required:"false"`
		ClientID         string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
	}
	CompletedRegistrationChallenge struct {
		*accounts.Credentials         `json:",inline"`
		ClientID                      string `header:"X-Client-ID" required:"true" swaggerignore:"true"`
		DeviceIdentificationRequestID string `header:"X-Device-Identification-Request-ID" required:"false" swaggerignore:"true"` // TODO: required: true once FE will send header.
		Authorization                 string `header:"Authorization" required:"true" swaggerignore:"true"`
	}
	CompletedRegistration = accounts.CompletedRegistration
	RegistrationChallenge = accounts.RegistrationChallenge
	EarlyAccessCheck      struct {
		Email string `form:"email" allowUnauthorized:"true" required:"true"`
	}
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
	GetBatchRelaysReq struct {
		MasterPubkeys []string `form:"masterPubkey" required:"true" swaggerignore:"true"`
	}
	AllRelaysReq struct {
		IONConnectRelay string `form:"ion-connect-relay" required:"true"`
	}
	HashtagsEventsReq struct {
		Events []*model.Event `json:"events" binding:"required,min=1,dive" allowUnauthorized:"true"`
	}
	NFTContentEventsReq struct {
		Events []*model.Event `json:"events" binding:"required,min=2,dive" allowUnauthorized:"true"`
	}
	FollowersEventsReq struct {
		Events []*model.Event `json:"events" binding:"required,min=2,max=2,dive" allowUnauthorized:"true"`
	}
	DeviceIdentificationEventReq struct {
		Event *model.Event `json:"event" binding:"required"`
	}
	GetTopHashtagsReq struct {
		Authorization string `header:"Authorization" required:"true" swaggerignore:"true"`
		Keyword       string `form:"keyword" required:"false"`
		Limit         int    `form:"limit" required:"false"`
	}
	GetNFTCollectionMetadataRequest struct {
		_              struct{} `json:"-" allowUnauthorized:"true"`
		NFTContentType string   `uri:"nftContentType" required:"true" binding:"oneof=user account post article video story"`
		ContentAddress string   `uri:"contentAddress" required:"true"`
	}
	GetNFTCollectionMetadataHtmlPreviewRequest struct {
		_              struct{} `json:"-" allowUnauthorized:"true"`
		NFTContentType string   `uri:"nftContentType" required:"true" binding:"oneof=account post article video story"`
		ContentAddress string   `uri:"contentAddress" required:"true"`
	}
	UserAssignedRelay = relaymanagement.UserAssignedRelay
	Relays            struct {
		IONConnectRelays []*UserAssignedRelay `json:"ionConnectRelays"`
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
	GetWalletViewReq struct {
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		WalletViewID      string `uri:"walletViewId" required:"true" swaggerignore:"true"`
		PaginationToken   string `query:"paginationToken" form:"paginationToken" required:"false"`
		Limit             uint   `query:"limit" form:"limit" required:"false"`
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
		WalletID        string `uri:"walletId"`
		PaginationToken string `query:"paginationToken" form:"paginationToken" required:"false"`
		Limit           uint   `query:"limit" form:"limit" required:"false"`
	}
	NFTCollection struct {
		WalletID        string       `json:"walletId"`
		Network         string       `json:"network"`
		NFTs            []*coins.NFT `json:"nfts"`
		PaginationToken *string      `json:"paginationToken,omitempty"`
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
	LiteUser                  = accounts.LiteUser
	SearchUserProfilesRequest struct {
		Authorization string `header:"Authorization" required:"true" swaggerignore:"true"`
		Keyword       string `form:"keyword" required:"true" swaggerignore:"true"`
		Limit         uint64 `form:"limit" required:"true" swaggerignore:"true"`
		Offset        uint64 `form:"offset" swaggerignore:"true"`
		Type          string `form:"type" required:"true" swaggerignore:"true"`
		FollowedBy    string `form:"followedBy" swaggerignore:"true"`
		FollowerOf    string `form:"followerOf" swaggerignore:"true"`
	}
	UpsertSocialProfileRequest struct {
		Authorization     string `header:"Authorization" required:"true" swaggerignore:"true" allowUnauthorized:"true"`
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
		Username          string `json:"username,omitempty"`
		DisplayName       string `json:"displayName,omitempty"`
		Referral          string `json:"referral,omitempty"`
		Avatar            string `json:"avatar,omitempty"`
		Bio               string `json:"bio,omitempty"`
	}
	GetSocialProfileRequest struct {
		Authorization     string `header:"Authorization" required:"true" swaggerignore:"true" allowUnauthorized:"true"`
		UserIDOrMasterKey string `uri:"userIdOrMasterKey" required:"true" swaggerignore:"true"`
	}
	VerifyUsernameRequest struct {
		Authorization string `header:"Authorization" required:"true" swaggerignore:"true"`
		Username      string `form:"username" required:"true"`
	}
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
	invalidEmail               = "INVALID_EMAIL"
	emailUsed                  = "EMAIL_USED"
	registrationsDisabled      = "REGISTRATIONS_DISABLED"
	reserved                   = "RESERVED"

	configNameRequiredAndroidAppVersion                            = "required_android_app_version"
	configNameRequiredIOSAppVersion                                = "required_ios_app_version"
	configNameRequiredMacOSAppVersion                              = "required_macos_app_version"
	configNameRequiredWindowsAppVersion                            = "required_windows_app_version"
	configNameRequiredLinuxAppVersion                              = "required_linux_app_version"
	configNameServicePubkeys                                       = "service_pubkeys"
	runtimeConfigApplicationYamlKey                                = "apps-runtime"
	configNameBlacklistedCountriesForPhone2FA                      = "blacklisted_countries_phone2fa"
	configNameTokenizedCommunitiesBondingCurveSmartContractABI     = "tokenized_communities_bonding_curve_smart_contract_abi"
	configNameTokenizedCommunitiesBondingCurveSmartContractAddress = "tokenized_communities_bonding_curve_smart_contract_address"
)

type (
	service struct {
		accounts                  accounts.Accounts
		coins                     coins.Coins
		relays                    relaymanagement.Relays
		hashtagStatistics         hashtagstatistics.HashtagStatistics
		nftContent                nftcontent.NFTContent
		following                 following.Following
		deviceIdentificationProxy accounts.DeviceIdentificationProxy
		validation                validation.Validator
		tokenAnalytics            tokenanalytics.TokenAnalytics
		cfg                       *config
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
		TokenizedCommunities struct {
			BondingCurveSmartContractAddress string  `yaml:"bondingCurveSmartContractAddress" mapstructure:"bondingCurveSmartContractAddress"`
			AddressVersion                   Version `yaml:"addressVersion" mapstructure:"addressVersion"`
			ABIVersion                       Version `yaml:"abiVersion" mapstructure:"abiVersion"`
		} `yaml:"tokenizedCommunities" mapstructure:"tokenizedCommunities"`
	}
)

var (
	//go:embed templates/*.html
	templates embed.FS
	//go:embed content-topics/*.json
	contentTopics embed.FS
	//go:embed translations/*/*.json
	translations        embed.FS
	allValidConfigNames = map[string]func(cfg *config, _ *Version) (any, Version){
		configNameRequiredAndroidAppVersion: func(cfg *config, _ *Version) (any, Version) { return cfg.RequiredAppVersions.Android, Version(0) },
		configNameRequiredIOSAppVersion:     func(cfg *config, _ *Version) (any, Version) { return cfg.RequiredAppVersions.IOS, Version(0) },
		configNameRequiredMacOSAppVersion:   func(cfg *config, _ *Version) (any, Version) { return cfg.RequiredAppVersions.MacOS, Version(0) },
		configNameRequiredWindowsAppVersion: func(cfg *config, _ *Version) (any, Version) { return cfg.RequiredAppVersions.Windows, Version(0) },
		configNameRequiredLinuxAppVersion:   func(cfg *config, _ *Version) (any, Version) { return cfg.RequiredAppVersions.Linux, Version(0) },
		configNameBlacklistedCountriesForPhone2FA: func(cfg *config, ver *Version) (any, Version) {
			if ver == nil {
				return errors.Wrapf(errVersionRequired, "version required for %s", configNameBlacklistedCountriesForPhone2FA), Version(0)
			}
			return blacklistedCountriesPhone2FA, Version(1)
		},
		configNameTokenizedCommunitiesBondingCurveSmartContractABI: func(cfg *config, ver *Version) (any, Version) {
			if ver == nil {
				return errors.Wrapf(errVersionRequired, "version required for %s", configNameTokenizedCommunitiesBondingCurveSmartContractABI), Version(0)
			}
			var rawJSONBody map[string]any
			if err := json.Unmarshal([]byte(tokenanalytics.TokenizedCommunitiesBondingCurveSmartContractABI()), &rawJSONBody); err != nil {
				return errors.Wrapf(err, "failed to parse `%v` cfg as JSON", configNameTokenizedCommunitiesBondingCurveSmartContractABI), Version(0)
			}

			return rawJSONBody, cfg.TokenizedCommunities.ABIVersion
		},
		configNameTokenizedCommunitiesBondingCurveSmartContractAddress: func(cfg *config, ver *Version) (any, Version) {
			if ver == nil {
				return errors.Wrapf(errVersionRequired, "version required for %s", configNameTokenizedCommunitiesBondingCurveSmartContractAddress), Version(0)
			}
			return cfg.TokenizedCommunities.BondingCurveSmartContractAddress, cfg.TokenizedCommunities.AddressVersion
		},
	}
	errVersionRequired           = errors.New("version required")
	blacklistedCountriesPhone2FA = []string{"AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AS", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BI", "BJ", "BL", "BM", "BO", "BQ", "BT", "BV", "BW", "BY", "BZ", "CC", "CD", "CF", "CG", "CI", "CK", "CM", "CN", "CU", "CV", "CW", "CX", "DE", "DJ", "DM", "DO", "DZ", "EC", "EG", "EH", "ER", "ET", "FJ", "FK", "FM", "FO", "GA", "GD", "GE", "GF", "GG", "GH", "GI", "GM", "GN", "GP", "GQ", "GS", "GT", "GY", "HM", "HN", "HR", "HT", "ID", "IL", "IM", "IN", "IO", "IQ", "IR", "JE", "JM", "JO", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "XK", "KW", "KY", "KZ", "LA", "LB", "LC", "LK", "LR", "LS", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "ML", "MM", "MN", "MP", "MQ", "MR", "MS", "MU", "MV", "MW", "MX", "MY", "MZ", "NC", "NE", "NF", "NG", "NI", "NL", "NP", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PM", "PN", "PS", "PW", "PY", "QA", "RE", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SH", "SI", "SJ", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TJ", "TK", "TL", "TM", "TN", "TO", "TT", "TV", "TZ", "UA", "UG", "UM", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"}
)
