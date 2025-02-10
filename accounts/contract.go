// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	_ "embed"
	"io"
	"math/big"
	"net/http"
	"sync"
	stdlibtime "time"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
	"github.com/ice-blockchain/wintr/totp"
)

type (
	Accounts interface {
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
		HealthCheck(ctx context.Context) error
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
		GetFees(network string) *coins.Fee
		ImportNFTs(ctx context.Context, network string, nft []coins.WalletNFT) ([]*NFT, error)
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
	WalletView struct {
		Name  string       `json:"name"`
		Coins CoinMappings `json:"coins"`
		// For GetWalletView, with total sum by symbol aggregation
		Aggregation  map[string]*CoinAggregation `json:"aggregation,omitempty"`
		SymbolGroups []string                    `json:"symbolGroups"`
		CreatedAt    *time.Time                  `json:"createdAt"`
		UpdatedAt    *time.Time                  `json:"updatedAt"`
		UserID       string                      `json:"userId"`
		ID           string                      `json:"id"`
	}
	CoinWithWalletInfo struct {
		*coins.Coin
		WalletID      string `json:"walletId"`
		WalletAddress string `json:"walletAddress"`
		Balance       string `json:"balance"`
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
	NFT    = coins.NFT
	Wallet = dfns.Wallet
)

const (
	TwoFAOptionSMS                   = TwoFAOptionEnum("sms")
	TwoFAOptionEmail                 = TwoFAOptionEnum("email")
	TwoFAOptionTOTPAuthenticator     = TwoFAOptionEnum("totp_authenticator")
	AuthorizationHeaderCtxValue      = dfns.AuthHeaderCtxValue
	AppIDHeaderCtxValue              = dfns.AppIDCtxValue
	UserActionCtxValue               = dfns.UserActionCtxValue
	UserSignatureCtxValueKey         = "UserSignatureCtxValueKey"
	registrationUrl                  = "/auth/registration/delegated"
	completeRegistrationUrl          = "/auth/registration/enduser"
	completeLoginUrl                 = "/auth/login"
	delegatedLoginUrl                = "/auth/login/delegated"
	defaultWalletViewCoinID          = "7b471f92-ced2-38b0-e408-88e5d89e8045"
	defaultWalletViewCoinSymbolGroup = coins.DefaultWalletViewCoinSymbolGroup
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
	ErrInvalidUsername                 = dfns.ErrInvalidUsername
	ErrNotChanged                      = errors.New("not changed")
	ErrDeleteLast                      = errors.New("cannot delete last entry")
	ErrRaceCondition                   = dfns.ErrRaceCondition
	ErrWalletLinked                    = errors.New("wallet already linked to walletview")
)

const (
	applicationYamlKey     = "accounts"
	clientIPCtxValueKey    = "clientIPCtxValueKey"
	confirmationCodeLength = 6
)

var (
	//go:embed DDL.sql
	ddl                  string
	errSignatureRequired = errors.New("signature is required")
	defaultCoins         []*coins.Coin
)

type (
	accounts struct {
		delegatedRPClient          dfns.DfnsClient
		totpProvider               totp.TOTP
		db                         *storage.DB
		coinsRepo                  Coins
		shutdown                   func() error
		emailSender                email.EmailSender
		smsSender                  sms.SmsSender
		concurrentlyGeneratedCodes map[TwoFAOptionEnum]*sync.Map
		cfg                        *config
	}
	user struct {
		CreatedAt                  *time.Time
		UpdatedAt                  *time.Time
		ID                         string
		Username                   string
		MasterPubKey               string `db:"master_pubkey"`
		Email                      []string
		PhoneNumber                []string
		TotpAuthenticatorSecret    []string
		IONConnectRelays           []string
		Clients                    []string
		Active2FAEmail             []bool `db:"active_2fa_email"`
		Active2FAPhoneNumber       []bool `db:"active_2fa_phone_number"`
		Active2FATotpAuthenticator []bool `db:"active_2fa_totp_authenticator"`
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
	}
)
