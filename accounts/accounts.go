// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	totp2 "github.com/ice-blockchain/wintr/totp"
)

func New(ctx context.Context) Accounts {
	cl := dfns.NewDfnsClient(ctx, applicationYamlKey)
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	totp := totp2.New(applicationYamlKey)
	em := email.New(applicationYamlKey)
	acc := accounts{dfnsClient: cl,
		db:           db,
		shutdown:     db.Close,
		totpProvider: totp,
		emailCode:    em,
	}
	return &acc
}
func (a *accounts) ProxyDfnsCall(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	a.dfnsClient.ProxyCall(ctx, rw, r)
}

func (a *accounts) Close() error {
	return errors.Wrapf(a.shutdown(), "failed to close accounts repository")
}
