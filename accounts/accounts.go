package accounts

import (
	"context"
	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"net/http"
)

func New(ctx context.Context) Accounts {
	cl := dfns.NewDfnsClient(ctx, applicationYamlKey)

	return &accounts{dfnsClient: cl}
}
func (a *accounts) ProxyDfnsCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	a.dfnsClient.ProxyCall(ctx, rw, r)
}
