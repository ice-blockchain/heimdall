// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	_ "embed"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"sync"
	stdlibtime "time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
	"github.com/ice-blockchain/wintr/totp"
)

type (
	SearchType = string
	Accounts   interface {
		io.Closer
		Wallets
		ProxyDelegatedRelyingParty(ctx context.Context, rw http.ResponseWriter, r *http.Request)
		Verify2FA(ctx context.Context, userID string, codes map[TwoFAOptionWithAddr]string) error
		Delete2FA(ctx context.Context, userID string, codes map[TwoFAOptionWithAddr]string, twoFAToDel TwoFAOptionEnum, toDel string) error
		Send2FA(ctx context.Context, userID string, channel TwoFAOptionEnum, deliverTo *string, language string, verificationUsingExisting2FA map[TwoFAOptionWithAddr]string, replaceOldValue *string) (authenticatorUri *string, err error)
		StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionWithAddr]string) (resp *StartedDelegatedRecovery, err error)
		GetLoginChallenge(ctx context.Context, username string, codes map[TwoFAOptionWithAddr]string) (*LoginChallenge, error)
		GetOrAssignIONConnectRelays(ctx context.Context, userID string, followees []string) (relays []string, err error)
		GetIONConnectIndexerRelays(ctx context.Context, userID string) (indexers []string, err error)
		GetUser(ctx context.Context, userID string) (usr *User, err error)
		SecurePaymentConfirmation(ctx context.Context, userID, walletID string, body map[string]string) (templateData any, err error)
		GetNFTs(ctx context.Context, walletID string) ([]*NFT, string, error)
		DeleteUser(ctx context.Context, userID string) error
		GetContentCreators(ctx context.Context, limit uint64, excludeMasterPubKeys []string) ([]*LiteUser, error)
		IsUserVerified(ctx context.Context, masterPubKey string) (bool, []*model.Event, error)
		HealthCheck(ctx context.Context) error
		PublicKey() string
		CompleteRegistration(ctx context.Context, credentials *Credentials) (CompletedRegistration, error)
		SocialProfiles
		EarlyAccessVerifier
	}
	VerifiedUsersSync interface {
		io.Closer
		ProcessNextVerifiedUsersQueue(ctx context.Context) error
		HealthCheck(ctx context.Context) error
	}
	SocialProfiles interface {
		VerifyUsernameAvailability(ctx context.Context, username string) error
		UpsertSocialProfile(ctx context.Context, userIDOrMasterKey, username, displayName string, referral string, loggedInUserUserID string) (*SocialProfile, error)
		SearchSocialProfiles(ctx context.Context, tpe SearchType, keyword string, limit uint64, offset uint64) ([]*LiteUser, error)
	}
	EarlyAccessVerifier interface {
		VerifyEarlyAccess(ctx context.Context, email string) error
	}
	Wallets interface {
		CreateWalletView(ctx context.Context, userID, name string, items []*CoinMapping, symbolGroups []string) (*WalletView, error)
		GetWalletViews(ctx context.Context, userID string) ([]*WalletView, error)
		GetWalletView(ctx context.Context, userID, id string) (*WalletView, error)
		DeleteWalletView(ctx context.Context, userID, id string) error
		ModifyWalletView(ctx context.Context, userID, id, newName string, items []*CoinMapping, symbolGroups []string) (*WalletView, error)
		GetCoinsOfSymbolGroup(ctx context.Context, userID, symbolGroup string) ([]*CoinWithWalletInfo, error)
		CreateWalletForWalletView(ctx context.Context, userID, network, walletViewID string) (*Wallet, error)
	}
	Coins interface {
		GetCoinsOfSymbolGroup(ctx context.Context, symbolGroups []string) ([]*coins.Coin, error)
		GetNativeCoinForNetwork(ctx context.Context, network string) (*coins.Coin, error)
		GetFees(network string) *coins.Fee
		ImportNFTs(ctx context.Context, network string, nft []coins.WalletNFT) ([]*NFT, error)
	}
	Relays interface {
		IONConnectRelaysForUser(ctx context.Context, userId string) ([]string, error)
	}
	TwoFAOptionEnum     string
	TwoFAOptionWithAddr struct {
		opt  TwoFAOptionEnum
		idx  int
		addr string
	} // email:someone@bogus.com, for the maps to separate codes for same channel
	StartedDelegatedRecovery = dfns.StartedDelegatedRecovery
	LoginChallenge           = dfns.LoginChallenge
	DelegatedRelyingPartyErr = dfns.DfnsInternalError
	BroadcastTxResponse      = dfns.BroadcastTxResponse
	User                     struct {
		dfns.User
		IONConnectRelays        []string          `json:"ionConnectRelays"`
		IONConnectIndexerRelays []string          `json:"ionConnectIndexerRelays"`
		Email                   []string          `json:"email,omitempty"`
		PhoneNumber             []string          `json:"phoneNumber,omitempty"`
		TwoFAOptions            []TwoFAOptionEnum `json:"2faOptions,omitempty"`
		MasterPubKey            string            `json:"masterPubKey"`
	}
	SocialProfile struct {
		Username          string         `json:"username,omitempty"`
		DisplayName       string         `json:"displayName,omitempty"`
		Referral          string         `json:"referral,omitempty"`
		ReferralMasterKey *string        `json:"referralMasterKey,omitempty"`
		UsernameProof     []*model.Event `json:"usernameProof,omitempty"`
	}
	WalletView struct {
		Name  string       `json:"name"`
		Coins CoinMappings `json:"coins"`
		// For GetWalletView, with total sum by symbol aggregation
		Aggregation map[string]*CoinAggregation `json:"aggregation,omitempty"`
		// For GetWalletView, all nfts from connected wallets
		NFTs         []*NFT     `json:"nfts,omitempty"`
		SymbolGroups []string   `json:"symbolGroups"`
		CreatedAt    *time.Time `json:"createdAt"`
		UpdatedAt    *time.Time `json:"updatedAt"`
		UserID       string     `json:"userId"`
		ID           string     `json:"id"`
	}
	CoinWithWalletInfo struct {
		*coins.Coin
		WalletID      *string `json:"walletId"`
		WalletAddress *string `json:"walletAddress"`
		Balance       string  `json:"balance"`
	}
	CoinMapping struct {
		*coins.Coin `swaggerignore:"true"`
		WalletID    *string `json:"walletId"`
		CoinID      string  `json:"coinId"`
	}
	CoinMappings []*CoinMapping
	CoinInWallet struct {
		Asset    *dfns.Asset `json:"asset"`
		WalletID string      `json:"walletId"`
		Network  string      `json:"network"`
		CoinID   string      `json:"coinId"`
	}
	CoinAggregation struct {
		TotalBalance *big.Int        `json:"totalBalance"`
		Wallets      []*CoinInWallet `json:"wallets"`
	}
	NFT      = coins.NFT
	Wallet   = dfns.Wallet
	LiteUser struct {
		MasterPubKey     string   `json:"masterPubKey" db:"master_pubkey"`
		IONConnectRelays []string `json:"ionConnectRelays" db:"ion_connect_relays"`
	}

	Credentials           = dfns.Credentials
	CompletedRegistration = dfns.CompletedRegistration
)

const (
	TwoFAOptionSMS                                 = TwoFAOptionEnum("sms")
	TwoFAOptionEmail                               = TwoFAOptionEnum("email")
	TwoFAOptionTOTPAuthenticator                   = TwoFAOptionEnum("totp_authenticator")
	AuthorizationHeaderCtxValue                    = dfns.AuthHeaderCtxValue
	AppIDHeaderCtxValue                            = dfns.AppIDCtxValue
	UserActionCtxValue                             = dfns.UserActionCtxValue
	UserSignatureCtxValueKey                       = "UserSignatureCtxValueKey"
	registrationUrl                                = "/auth/registration/delegated"
	completeRegistrationUrl                        = "/auth/registration/enduser"
	completeLoginUrl                               = "/auth/login"
	delegatedLoginUrl                              = "/auth/login/delegated"
	defaultWalletViewCoinID                        = coins.DefaultWalletViewCoinID
	defaultWalletViewCoinSymbolGroup               = "ion" // TODO: update coins.DefaultWalletViewCoinSymbolGroup once ion updated on coin gecko
	defaultWalletViewCoinSymbolGroupForOldAccounts = "the-open-network"
	defaultWalletViewName                          = "ion.wallet"

	verifiedBadgeDTag        = "verified"
	verifiedBadgeName        = "Verified by ION Identity"
	verifiedBadgeDescription = "Awarded to users that are verified by ION Identity"

	SearchTypeContains   SearchType = "contains"
	SearchTypeStartsWith SearchType = "startsWith"
)

var (
	AllTwoFAOptions = []TwoFAOptionEnum{
		TwoFAOptionSMS,
		TwoFAOptionEmail,
		TwoFAOptionTOTPAuthenticator,
	}
	Err2FADeliverToNotProvided         = errors.New("no email or phone number provided for 2FA")
	ErrNoPending2FA                    = errors.New("no pending 2FA request")
	Err2FAExpired                      = errors.New("2FA request expired")
	Err2FAInvalidCode                  = errors.New("invalid code")
	Err2FARequired                     = errors.New("2FA required")
	ErrAuthenticatorRequirementsNotMet = errors.New("authenticator requirements not met")
	ErrNotFound                        = storage.ErrNotFound
	ErrDuplicate                       = storage.ErrDuplicate
	ErrInvalidFollowees                = errors.New("invalid followees")
	ErrInvalidUserSignature            = errors.New("invalid user signature")
	ErrInvalidIdentityKey              = dfns.ErrInvalidUsername
	ErrInvalidUsername                 = errors.New("invalid username")
	ErrNotChanged                      = errors.New("not changed")
	ErrDeleteLast                      = errors.New("cannot delete last entry")
	ErrRaceCondition                   = dfns.ErrRaceCondition
	ErrWalletLinked                    = errors.New("wallet already linked to walletview")
	ErrUnauthorized                    = errors.New("unauthorized")
	ErrWrongReferral                   = errors.New("wrong/circular referral detected")
	ErrRegistrationsDisabled           = &dfns.DfnsInternalError{HTTPStatus: http.StatusForbidden, Message: "registrations disabled"}
	ErrEmailNotAllowedForEarlyAccess   = &dfns.DfnsInternalError{HTTPStatus: http.StatusForbidden, Message: "email not allowed for early access"}
	ErrEmailUsed                       = &dfns.DfnsInternalError{HTTPStatus: http.StatusForbidden, Message: "email used"}
	verifiedBadgeImage1024X1024Tag     = nostr.Tag{"image", "https://example.com/verified_1024x1024.webp", "1024x1024"}
	verifiedBadgeThumbnail256X256Tag   = nostr.Tag{"thumb", "https://example.com/verified_256x256.webp", "256x256"}
)

const (
	applicationYamlKey     = "accounts"
	clientIPCtxValueKey    = "clientIPCtxValueKey"
	confirmationCodeLength = 6

	usernameProofOfOwnershipBadgeName = "username_proof_of_ownership"
)

var (
	//go:embed DDL.sql
	ddl                  string
	errSignatureRequired = errors.New("signature is required")
	defaultCoins         map[string][]*coins.Coin

	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9.]{1,20}$`)
)

type (
	accounts struct {
		delegatedRPClient          dfns.DfnsClient
		totpProvider               totp.TOTP
		db                         *storage.DB
		coinsRepo                  Coins
		relaysRepo                 Relays
		shutdown                   func() error
		emailSender                email.EmailSender
		smsSender                  sms.SmsSender
		concurrentlyGeneratedCodes map[TwoFAOptionEnum]*sync.Map
		cfg                        *config
		privateKey                 string
		appsRuntimeConfig          *AppsRuntimeConfig
	}
	verifiedUsersSync struct {
		db         *storage.DB
		shutdown   func() error
		privateKey string
	}
	user struct {
		CreatedAt                  *time.Time
		UpdatedAt                  *time.Time
		ID                         string
		IdentityKeyName            string `db:"identity_key_name"`
		MasterPubKey               string `db:"master_pubkey"`
		Email                      []string
		PhoneNumber                []string
		TotpAuthenticatorSecret    []string
		IONConnectRelays           []string
		Clients                    []string
		Active2FAEmail             []bool `db:"active_2fa_email"`
		Active2FAPhoneNumber       []bool `db:"active_2fa_phone_number"`
		Active2FATotpAuthenticator []bool `db:"active_2fa_totp_authenticator"`
		Verified                   bool   `db:"verified"`
	}
	socialProfile struct {
		CreatedAt            *time.Time
		UpdatedAt            *time.Time
		MasterPubkey         string  `db:"master_pubkey"`
		Username             string  `db:"username"`
		DisplayName          string  `db:"display_name"`
		ReferralMasterPubkey *string `db:"referral_master_pubkey"`
	}
	twoFACode struct {
		CreatedAt       *time.Time
		ConfirmedAt     *time.Time
		UserID          string
		Option          TwoFAOptionEnum
		DeliverTo       string
		ReplaceOldValue *string `db:"replace"`
		Code            string
	}
	config struct {
		EmailExpiration          stdlibtime.Duration `yaml:"emailExpiration" mapstructure:"emailExpiration"`
		SMSExpiration            stdlibtime.Duration `yaml:"smsExpiration" mapstructure:"smsExpiration"`
		UserSignatureExpiration  stdlibtime.Duration `yaml:"userSignatureExpiration" mapstructure:"userSignatureExpiration"`
		Max2FACount              int                 `yaml:"max2FACount" mapstructure:"max2FACount"`
		DefaultCoinsInWalletView []string            `yaml:"defaultCoinsInWalletView" mapstructure:"defaultCoinsInWalletView"`
		MockRelays               []string            `yaml:"mockRelays" mapstructure:"mockRelays"`
		PrivateKey               string              `yaml:"privateKey" mapstructure:"privateKey"`
		RelaysPerUser            uint8               `yaml:"relaysPerUser" mapstructure:"relaysPerUser"`
	}

	AppsRuntimeConfig struct {
		IONApp AppRuntimeConfig `yaml:"ion-app" mapstructure:"ion-app"`
	}
	AppRuntimeConfig struct {
		Version                                    int     `yaml:"_version" mapstructure:"_version" json:"_version"`
		InterestedThreshold                        float64 `yaml:"interestedThreshold" mapstructure:"interestedThreshold" json:"interestedThreshold"`
		NotInterestedCategoryChance                float64 `yaml:"notInterestedCategoryChance" mapstructure:"notInterestedCategoryChance" json:"notInterestedCategoryChance"`
		NotInterestedSubcategoryChance             float64 `yaml:"notInterestedSubcategoryChance" mapstructure:"notInterestedSubcategoryChance" json:"notInterestedSubcategoryChance"`
		ForYouMaxRetriesMultiplier                 float64 `yaml:"forYouMaxRetriesMultiplier" mapstructure:"forYouMaxRetriesMultiplier" json:"forYouMaxRetriesMultiplier"`
		FollowingMaxRetriesMultiplier              float64 `yaml:"followingMaxRetriesMultiplier" mapstructure:"followingMaxRetriesMultiplier" json:"followingMaxRetriesMultiplier"`
		ConcurrentRequests                         int     `yaml:"concurrentRequests" mapstructure:"concurrentRequests" json:"concurrentRequests"`
		FollowingReqMaxAge                         int     `yaml:"followingReqMaxAge" mapstructure:"followingReqMaxAge" json:"followingReqMaxAge"`
		FollowingCacheMaxAge                       int     `yaml:"followingCacheMaxAge" mapstructure:"followingCacheMaxAge" json:"followingCacheMaxAge"`
		TopMaxAge                                  int     `yaml:"topMaxAge" mapstructure:"topMaxAge" json:"topMaxAge"`
		TrendingMaxAge                             int     `yaml:"trendingMaxAge" mapstructure:"trendingMaxAge" json:"trendingMaxAge"`
		ExploreMaxAge                              int     `yaml:"exploreMaxAge" mapstructure:"exploreMaxAge" json:"exploreMaxAge"`
		RepostThrottleDelay                        int     `yaml:"repostThrottleDelay" mapstructure:"repostThrottleDelay" json:"repostThrottleDelay"`
		ConcurrentMediaDownloadsLimit              int     `yaml:"concurrentMediaDownloadsLimit" mapstructure:"concurrentMediaDownloadsLimit" json:"concurrentMediaDownloadsLimit"`
		ExcludeUnclassifiedFromExplore             bool    `yaml:"excludeUnclassifiedFromExplore" mapstructure:"excludeUnclassifiedFromExplore" json:"excludeUnclassifiedFromExplore"`
		AllowNewRegistrations                      bool    `yaml:"allowNewRegistrations" mapstructure:"allowNewRegistrations" json:"allowNewRegistrations"`
		EnableEarlyAccessRegistrations             bool    `yaml:"enableEarlyAccessRegistrations" mapstructure:"enableEarlyAccessRegistrations" json:"enableEarlyAccessRegistrations"`
		MaxEarlyAccessRegistrationsAllowedPerEmail int     `yaml:"maxEarlyAccessRegistrationsAllowedPerEmail" mapstructure:"maxEarlyAccessRegistrationsAllowedPerEmail" json:"maxEarlyAccessRegistrationsAllowedPerEmail"`
	}
)
