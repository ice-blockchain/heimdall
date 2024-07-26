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
)

const applicationYamlKey = "accounts"

type (
	accounts struct {
		dfnsClient dfns.DfnsClient
	}
)
