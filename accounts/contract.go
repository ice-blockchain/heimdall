// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	_ "embed"
	"io"
	"net/http"

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
	}

	TwoFAOptionEnum = string
)

const (
	TwoFAOptionSMS                 = TwoFAOptionEnum("sms")
	TwoFAOptionEmail               = TwoFAOptionEnum("email")
	TwoFAOptionTOTPAuthentificator = TwoFAOptionEnum("google_authentificator")
)

var (
	AllTwoFAOptions = []TwoFAOptionEnum{
		TwoFAOptionSMS,
		TwoFAOptionEmail,
		TwoFAOptionTOTPAuthentificator,
	}
	Err2FAAlreadySetup         = errors.New("2FA already set up")
	Err2FADeliverToNotProvided = errors.New("no email or phone number provided for 2FA")
)

const applicationYamlKey = "accounts"

//go:embed DDL.sql
var ddl string

type (
	accounts struct {
		dfnsClient   dfns.DfnsClient
		totpProvider totp.TOTP
		db           *storage.DB
		shutdown     func() error
		emailCode    email.EmailSender
	}
	user struct {
		ID                        string
		Email                     *string
		PhoneNumber               *string
		TotpAuthentificatorSecret *string `db:"totp_authentificator_secret"`
	}
	twoFACode struct {
		CreatedAt *time.Time
		UserID    string
		Option    TwoFAOptionEnum
		DeliverTo string
		Code      string
	}
)
