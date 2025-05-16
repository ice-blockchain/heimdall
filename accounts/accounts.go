// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/accounts/internal/email"
	"github.com/ice-blockchain/heimdall/accounts/internal/sms"
	"github.com/ice-blockchain/heimdall/coins"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/totp"
)

func NewDelegatedRPAuth(ctx context.Context) dfns.AuthClient {
	return dfns.NewDfnsTokenAuth(ctx, applicationYamlKey)
}

func New(ctx context.Context, coinsRepo Coins) Accounts {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	cl := dfns.NewDfnsClient(ctx, db, applicationYamlKey, coinsRepo)

	var cfg config
	if cfg.RelaysPerUser == 0 {
		cfg.RelaysPerUser = 1
	}
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	var smsSender sms.SmsSender
	func() {
		defer func() {
			if e := recover(); e != nil {
				var development bool
				appcfg.MustLoadFromKey("development", &development)
				if !development {
					log.Panic(e)
				}
				log.Error(errors.Errorf("%v", e))
			}
		}()
		smsSender = sms.New(applicationYamlKey)
	}()
	if cfg.PrivateKey == "" {
		panic("[accounts] private key is not set")
	}
	acc := accounts{
		db:                         db,
		coinsRepo:                  coinsRepo,
		shutdown:                   db.Close,
		totpProvider:               totp.New(applicationYamlKey),
		emailSender:                email.New(applicationYamlKey),
		smsSender:                  smsSender,
		cfg:                        &cfg,
		concurrentlyGeneratedCodes: make(map[TwoFAOptionEnum]*sync.Map),
		privateKey:                 cfg.PrivateKey,
	}
	cl.RegisterPostProxyCallback(registrationUrl, acc.upsertUsernameFromRegistration)
	cl.RegisterPostProxyCallback(completeLoginUrl, acc.upsertUsernameFromLogin)
	cl.RegisterPostProxyCallback(delegatedLoginUrl, acc.upsertUsernameFromLogin)
	cl.RegisterPostProxyCallback(completeRegistrationUrl, acc.upsertWalletPubKeyFromRegistrationAndRegisterWalletView)
	acc.delegatedRPClient = cl
	for _, opt := range AllTwoFAOptions {
		acc.concurrentlyGeneratedCodes[opt] = &sync.Map{}
	}
	defCoinsList, err := coinsRepo.GetCoinsOfSymbolGroup(ctx, acc.cfg.DefaultCoinsInWalletView)
	log.Panic(errors.Wrapf(err, "failed to load default coins list from db for list: %v", acc.cfg.DefaultCoinsInWalletView))
	defaultCoins = make(map[string][]*coins.Coin)
	for _, dc := range defCoinsList {
		defaultCoins[dc.SymbolGroup] = append(defaultCoins[dc.SymbolGroup], dc)
	}

	return &acc
}

func NewVerifiedQueueRepository(ctx context.Context) VerifiedUsersSync {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.PrivateKey == "" {
		panic("[verified-users-sync] private key is not set")
	}

	vSync := verifiedUsersSync{
		db:         db,
		shutdown:   db.Close,
		privateKey: cfg.PrivateKey,
	}

	return &vSync
}

func (a *accounts) Close() error {
	return errors.Wrapf(a.shutdown(), "failed to close accounts repository")
}

func (a *verifiedUsersSync) Close() error {
	return errors.Wrapf(a.shutdown(), "failed to close verified users sync repository")
}

func (a *accounts) HealthCheck(ctx context.Context) error {
	if err := a.db.Ping(ctx); err != nil {
		return errors.Wrap(err, "[health-check] failed to ping DB")
	}
	return nil
}

func (a *verifiedUsersSync) HealthCheck(ctx context.Context) error {
	if err := a.db.Ping(ctx); err != nil {
		return errors.Wrap(err, "[health-check] failed to ping DB")
	}
	return nil
}

func ParseErrAsDelegatedInternalErr(err error) error {
	return dfns.ParseErrAsDfnsInternalErr(err)
}
