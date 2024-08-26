// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	"sync"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
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

	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	acc := accounts{delegatedRPClient: cl,
		db:                         db,
		shutdown:                   db.Close,
		totpProvider:               totp.New(applicationYamlKey),
		emailSender:                email.New(applicationYamlKey),
		smsSender:                  sms.New(applicationYamlKey),
		cfg:                        &cfg,
		concurrentlyGeneratedCodes: make(map[TwoFAOptionEnum]*sync.Map),
	}
	for _, opt := range AllTwoFAOptions {
		acc.concurrentlyGeneratedCodes[opt] = &sync.Map{}
	}
	return &acc
}

func (a *accounts) Close() error {
	return errors.Wrapf(a.shutdown(), "failed to close accounts repository")
}

func (a *accounts) HealthCheck(ctx context.Context) error {
	if err := a.db.Ping(ctx); err != nil {
		return errors.Wrap(err, "[health-check] failed to ping DB")
	}
	return nil
}

func ParseErrAsDelegatedInternalErr(err error) error {
	return dfns.ParseErrAsDfnsInternalErr(err)
}
