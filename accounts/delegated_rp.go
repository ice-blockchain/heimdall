// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/terror"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) ProxyDelegatedRelyingParty(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	now := time.Now()
	respBody := a.delegatedRPClient.ProxyCall(ctx, rw, r)
	if r.URL.Path == registrationUrl {
		log.Error(errors.Wrapf(a.upsertUsername(ctx, now, respBody), "failed to store username for user on registration"))
	}
}

func (a *accounts) StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionEnum]string) (*StartedDelegatedRecovery, error) {
	usr, err := a.getUserByUsername(ctx, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user 2FA state for username %v", username)
	}
	twoFARequired := make([]TwoFAOptionEnum, 0, len(AllTwoFAOptions))
	for _, opt := range AllTwoFAOptions {
		if err = checkIf2FARequired(usr, opt, codes); err != nil {
			twoFARequired = append(twoFARequired, opt)
		}
	}
	if len(twoFARequired) > 0 {
		return nil, terror.New(Err2FARequired, map[string]any{
			"options": twoFARequired,
		})
	}
	var rollbackCodes map[TwoFAOptionEnum]string
	if rollbackCodes, err = a.verify2FA(ctx, usr.ID, codes); err != nil {
		return nil, errors.Wrapf(err, "failed to verify 2FA codes")
	}
	var delegatedResp *StartedDelegatedRecovery
	delegatedResp, err = a.delegatedRPClient.StartDelegatedRecovery(ctx, username, credentialID)
	if err != nil {
		log.Error(errors.Wrapf(a.rollbackRedeemed2FACodes(usr.ID, rollbackCodes), "failed to rollback used 2fa codes "))
		return nil, errors.Wrapf(err, "failed to start delegated recovery for username %v", username)
	}
	return delegatedResp, nil
}

func checkIf2FARequired(usr *user, opt TwoFAOptionEnum, codes map[TwoFAOptionEnum]string) error {
	var field []string
	switch opt {
	case TwoFAOptionEmail:
		field = usr.Email
	case TwoFAOptionSMS:
		field = usr.PhoneNumber
	case TwoFAOptionTOTPAuthentificator:
		field = usr.TotpAuthentificatorSecret
	default:
		log.Panic(errors.Errorf("unknown 2FA option %v", opt))
	}
	if len(field) > 0 {
		if _, presented := codes[opt]; !presented {
			return Err2FARequired
		}
	}
	return nil
}
