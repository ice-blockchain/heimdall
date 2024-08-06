// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	_ "embed"
	"io"
	"net/http"
	stdlibtime "time"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
	"github.com/ice-blockchain/wintr/totp"
)

type (
	Accounts interface {
		io.Closer
		ProxyDfnsCall(ctx context.Context, rw http.ResponseWriter, r *http.Request)
		Verify2FA(ctx context.Context, userID string, codes map[TwoFAOptionEnum]string) error
		Send2FA(ctx context.Context, userID string, channel TwoFAOptionEnum, deliverTo *string, language string) (authentificatorUri *string, err error)
		StartDelegatedRecovery(ctx context.Context, userID string, codes map[TwoFAOptionEnum]string, dfnsUsername, credentialID string) (resp *StartedDelegatedRecovery, err error)
		GetIONRelays(ctx context.Context, userID string, followees []string) (relays []string, err error)
		GetIONIndexers(ctx context.Context, userID string) (indexers []string, err error)
		GetUser(ctx context.Context, userID string) (usr *User, err error)
	}

	TwoFAOptionEnum          = string
	StartedDelegatedRecovery = dfns.StartedDelegatedRecovery
	DfnsErr                  = dfns.DfnsInternalError
	User                     struct {
		*dfns.User
		IONRelays    []string          `json:"ionRelays"`
		IONIndexers  []string          `json:"ionIndexers"`
		Email        string            `json:"email,omitempty"`
		PhoneNumber  string            `json:"phoneNumber,omitempty"`
		TwoFAOptions []TwoFAOptionEnum `json:"2faOptions"`
	}
)

const (
	TwoFAOptionSMS                  = TwoFAOptionEnum("sms")
	TwoFAOptionEmail                = TwoFAOptionEnum("email")
	TwoFAOptionTOTPAuthentificator  = TwoFAOptionEnum("google_authentificator")
	DfnsAuthorizationHeaderCtxValue = dfns.AuthHeaderCtxValue
	DfnsAppIDHeaderCtxValue         = dfns.AppIDCtxValue
)

var (
	AllTwoFAOptions = []TwoFAOptionEnum{
		TwoFAOptionSMS,
		TwoFAOptionEmail,
		TwoFAOptionTOTPAuthentificator,
	}
	Err2FAAlreadySetup         = errors.New("2FA already set up")
	Err2FADeliverToNotProvided = errors.New("no email or phone number provided for 2FA")
	ErrNoPending2FA            = errors.New("no pending 2FA request")
	Err2FAExpired              = errors.New("2FA request expired")
	Err2FAInvalidCode          = errors.New("invalid code")
	Err2FARequired             = errors.New("2FA required")
)

const (
	applicationYamlKey  = "accounts"
	clientIPCtxValueKey = "clientIPCtxValueKey"
)

//go:embed DDL.sql
var ddl string

type (
	accounts struct {
		dfnsClient   dfns.DfnsClient
		totpProvider totp.TOTP
		db           *storage.DB
		shutdown     func() error
		emailCode    email.EmailSender
		cfg          *config
	}
	user struct {
		ID                        string
		Email                     *string
		PhoneNumber               *string
		TotpAuthentificatorSecret *string
		IONRelays                 []string
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
		EmailExpiration stdlibtime.Duration `yaml:"emailExpiration"`
		SMSExpiration   stdlibtime.Duration `yaml:"smsExpiration"`
	}
)
