// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	totp2 "github.com/ice-blockchain/wintr/totp"
)

func New(ctx context.Context) Accounts {
	cl, whSecret := dfns.NewDfnsClient(ctx, applicationYamlKey)
	db := storage.MustConnect(ctx, fmt.Sprintf(ddl, whSecret), applicationYamlKey)
	totp := totp2.New(applicationYamlKey)
	em := email.New(applicationYamlKey)
	var smsSender sms.SmsSender
	if false { // TODO: creds
		smsSender = sms.New(applicationYamlKey)
	}

	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	acc := accounts{dfnsClient: cl,
		db:           db,
		shutdown:     db.Close,
		totpProvider: totp,
		emailSender:  em,
		smsSender:    smsSender,
		cfg:          &cfg,
	}
	return &acc
}

func (a *accounts) Close() error {
	return errors.Wrapf(a.shutdown(), "failed to close accounts repository")
}

func ParseErrAsDfnsInternalErr(err error) error {
	return dfns.ParseErrAsDfnsInternalErr(err)
}
