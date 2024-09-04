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
		Verify2FA(ctx context.Context, userID string, codes map[TwoFAOptionEnum]string) error
		Delete2FA(ctx context.Context, userID string, codes map[TwoFAOptionEnum]string, twoFAToDel TwoFAOptionEnum, toDel string) error
		Send2FA(ctx context.Context, userID string, channel TwoFAOptionEnum, deliverTo *string, language string, verificationUsingExisting2FA map[TwoFAOptionEnum]string) (authentificatorUri *string, err error)
		StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionEnum]string) (resp *StartedDelegatedRecovery, err error)
		GetOrAssignIONConnectRelays(ctx context.Context, userID string, followees []string) (relays []string, err error)
		GetIONConnectIndexerRelays(ctx context.Context, userID string) (indexers []string, err error)
		GetUser(ctx context.Context, userID string) (usr *User, err error)
		HealthCheck(ctx context.Context) error
	}

	TwoFAOptionEnum          = string
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
	TwoFAOptionSMS                 = TwoFAOptionEnum("sms")
	TwoFAOptionEmail               = TwoFAOptionEnum("email")
	TwoFAOptionTOTPAuthentificator = TwoFAOptionEnum("totp_authentificator")
	AuthorizationHeaderCtxValue    = dfns.AuthHeaderCtxValue
	AppIDHeaderCtxValue            = dfns.AppIDCtxValue
	registrationUrl                = "/auth/registration/delegated"
	completeLoginUrl               = "/auth/login"
	delegatedLoginUrl              = "/auth/login/delegated"
)

var (
	AllTwoFAOptions = []TwoFAOptionEnum{
		TwoFAOptionSMS,
		TwoFAOptionEmail,
		TwoFAOptionTOTPAuthentificator,
	}
	Err2FAAlreadySetup                   = errors.New("2FA already set up")
	Err2FADeliverToNotProvided           = errors.New("no email or phone number provided for 2FA")
	ErrNoPending2FA                      = errors.New("no pending 2FA request")
	Err2FAExpired                        = errors.New("2FA request expired")
	Err2FAInvalidCode                    = errors.New("invalid code")
	Err2FARequired                       = errors.New("2FA required")
	ErrAuthentificatorRequirementsNotMet = errors.New("authentificator requirements not met")
	ErrUserNotFound                      = storage.ErrNotFound
)

const (
	applicationYamlKey     = "accounts"
	clientIPCtxValueKey    = "clientIPCtxValueKey"
	confirmationCodeLength = 6
)

//go:embed DDL.sql
var ddl string

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
		CreatedAt                    *time.Time
		UpdatedAt                    *time.Time
		ID                           string
		Username                     string
		Email                        []string
		PhoneNumber                  []string
		TotpAuthentificatorSecret    []string
		IONConnectRelays             []string
		Clients                      []string
		Active2FAEmail               *int `db:"active_2fa_email"`
		Active2FAPhoneNumber         *int `db:"active_2fa_phone_number"`
		Active2FATotpAuthentificator *int `db:"active_2fa_totp_authentificator"`
	}
	twoFACode struct {
		CreatedAt   *time.Time
		ConfirmedAt *time.Time
		UserID      string
		Option      TwoFAOptionEnum
		DeliverTo   string
		Code        string
	}
	config struct {
		EmailExpiration stdlibtime.Duration `yaml:"emailExpiration" mapstructure:"emailExpiration"`
		SMSExpiration   stdlibtime.Duration `yaml:"smsExpiration" mapstructure:"smsExpiration"`
	}
)
