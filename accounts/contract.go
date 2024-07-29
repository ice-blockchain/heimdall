package accounts

import (
	"context"
	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"net/http"
)

type (
	Accounts interface {
		ProxyDfnsCall(ctx context.Context, rw http.ResponseWriter, r *http.Request)
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
)

const applicationYamlKey = "accounts"

type (
	accounts struct {
		dfnsClient dfns.DfnsClient
	}
)
