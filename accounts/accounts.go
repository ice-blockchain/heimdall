// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"

	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/totp"
)

func NewDelegatedRPAuth(ctx context.Context) dfns.AuthClient {
	return dfns.NewDfnsTokenAuth(ctx, applicationYamlKey)
}

func New(ctx context.Context) Accounts {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	cl := dfns.NewDfnsClient(ctx, db, applicationYamlKey)
	totpAuth := totp.New(applicationYamlKey)
	em := email.New(applicationYamlKey)
	var smsSender sms.SmsSender
	if false { // TODO: creds
		smsSender = sms.New(applicationYamlKey)
	}

	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	acc := accounts{delegatedRPClient: cl,
		db:                   db,
		shutdown:             db.Close,
		totpProvider:         totpAuth,
		emailSender:          em,
		smsSender:            smsSender,
		cfg:                  &cfg,
		singleCodesGenerator: make(map[TwoFAOptionEnum]*singleflight.Group),
	}
	for _, opt := range AllTwoFAOptions {
		acc.singleCodesGenerator[opt] = &singleflight.Group{}
	}
	return &acc
}

func (a *accounts) Close() error {
	return errors.Wrapf(a.shutdown(), "failed to close accounts repository")
}

func ParseErrAsDelegatedInternalErr(err error) error {
	return dfns.ParseErrAsDfnsInternalErr(err)
}
