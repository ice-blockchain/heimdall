// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/http"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) ProxyDelegatedRelyingParty(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	now := time.Now()
	respBody := a.delegatedRPClient.ProxyCall(ctx, rw, r)
	switch r.URL.Path {
	case registrationUrl:
		log.Error(errors.Wrapf(a.upsertUsernameFromRegistration(ctx, now, respBody), "failed to store username for user on registration"))
	case completeLoginUrl, delegatedLoginUrl:
		log.Error(errors.Wrapf(a.upsertUsernameFromLogin(ctx, now, respBody), "failed to store username for user on login (%v)", r.URL.Path))
	}
}

func (a *accounts) StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionEnum]string) (*StartedDelegatedRecovery, error) {
	usr, err := a.getUserByUsername(ctx, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user 2FA state for username %v", username)
	}
	if err = checkIfAll2FAProvided(usr, codes); err != nil {
		return nil, err //nolint:wrapcheck // tErr.
	}
	var rollbackCodes map[TwoFAOptionEnum]string
	if rollbackCodes, err = a.verifyAndRedeem2FA(ctx, usr.ID, codes); err != nil {
		return nil, errors.Wrapf(err, "failed to verify 2FA codes")
	}
	var delegatedResp *StartedDelegatedRecovery
	delegatedResp, err = a.delegatedRPClient.StartDelegatedRecovery(ctx, username, credentialID)
	if err != nil {
		return nil, multierror.Append(
			errors.Wrapf(err, "failed to start delegated recovery for username %v", username),
			errors.Wrapf(a.rollbackRedeemed2FACodes(usr.ID, rollbackCodes), "failed to rollback used 2fa codes for userID %v", usr.ID),
		)
	}
	return delegatedResp, nil
}
