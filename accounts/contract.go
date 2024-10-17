// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	_ "embed"
	"io"
	"net/http"
	"sync"
	stdlibtime "time"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
	"github.com/ice-blockchain/wintr/totp"
)

type (
	Accounts interface {
		io.Closer
		ProxyDelegatedRelyingParty(ctx context.Context, rw http.ResponseWriter, r *http.Request)
		Verify2FA(ctx context.Context, userID string, codes map[TwoFAOptionWithAddr]string) error
		Delete2FA(ctx context.Context, userID string, codes map[TwoFAOptionWithAddr]string, twoFAToDel TwoFAOptionEnum, toDel string) error
		Send2FA(ctx context.Context, userID string, channel TwoFAOptionEnum, deliverTo *string, language string, verificationUsingExisting2FA map[TwoFAOptionWithAddr]string) (authenticatorUri *string, err error)
		StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionWithAddr]string) (resp *StartedDelegatedRecovery, err error)
		GetOrAssignIONConnectRelays(ctx context.Context, userID string, followees []string) (relays []string, err error)
		GetIONConnectIndexerRelays(ctx context.Context, userID string) (indexers []string, err error)
		GetUser(ctx context.Context, userID string) (usr *User, err error)
		HealthCheck(ctx context.Context) error
	}

	TwoFAOptionEnum     string
	TwoFAOptionWithAddr struct {
		opt  TwoFAOptionEnum
		idx  int
		addr string
	} // email:someone@bogus.com, for the maps to separate codes for same channel
	StartedDelegatedRecovery = dfns.StartedDelegatedRecovery
	DelegatedRelyingPartyErr = dfns.DfnsInternalError
	User                     struct {
		dfns.User
		IONConnectRelays        []string          `json:"ionConnectRelays"`
		IONConnectIndexerRelays []string          `json:"ionConnectIndexerRelays"`
		Email                   []string          `json:"email,omitempty"`
		PhoneNumber             []string          `json:"phoneNumber,omitempty"`
		TwoFAOptions            []TwoFAOptionEnum `json:"2faOptions"`
	}
)

const (
	TwoFAOptionSMS               = TwoFAOptionEnum("sms")
	TwoFAOptionEmail             = TwoFAOptionEnum("email")
	TwoFAOptionTOTPAuthenticator = TwoFAOptionEnum("totp_authenticator")
	AuthorizationHeaderCtxValue  = dfns.AuthHeaderCtxValue
	AppIDHeaderCtxValue          = dfns.AppIDCtxValue
	registrationUrl              = "/auth/registration/delegated"
	completeRegistrationUrl      = "/auth/registration/enduser"
	completeLoginUrl             = "/auth/login"
	delegatedLoginUrl            = "/auth/login/delegated"
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
	ErrUserNotFound                    = storage.ErrNotFound
	ErrInvalidFollowees                = errors.New("invalid followees")
	ErrInvalidUserSignature            = errors.New("invalid user signature")
	ErrInvalidUsername                 = dfns.ErrInvalidUsername
)

const (
	applicationYamlKey       = "accounts"
	clientIPCtxValueKey      = "clientIPCtxValueKey"
	userSignatureCtxValueKey = "userSignatureCtxValueKey"
	confirmationCodeLength   = 6
)

var (
	//go:embed DDL.sql
	ddl                  string
	errSignatureRequired = errors.New("signature is required")
)

type (
	accounts struct {
		delegatedRPClient          dfns.DfnsClient
		totpProvider               totp.TOTP
		db                         *storage.DB
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
		CreatedAt    *time.Time
		ConfirmedAt  *time.Time
		UserID       string
		Option       TwoFAOptionEnum
		DeliverToIdx *int `db:"deliver_to_idx"`
		DeliverTo    string
		Code         string
	}
	config struct {
		EmailExpiration         stdlibtime.Duration `yaml:"emailExpiration" mapstructure:"emailExpiration"`
		SMSExpiration           stdlibtime.Duration `yaml:"smsExpiration" mapstructure:"smsExpiration"`
		UserSignatureExpiration stdlibtime.Duration `yaml:"userSignatureExpiration" mapstructure:"userSignatureExpiration"`
		Max2FACount             int                 `yaml:"max2FACount" mapstructure:"max2FACount"`
	}
)
