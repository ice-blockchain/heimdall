// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
)

func (a *accounts) ProxyDelegatedRelyingParty(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	a.delegatedRPClient.ProxyCall(ctx, rw, r)
}

func (a *accounts) StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionWithAddr]string) (*StartedDelegatedRecovery, error) {
	username = strings.ToLower(username)
	if !dfns.UsernameRegexp.MatchString(username) {
		return nil, errors.Wrapf(dfns.ErrInvalidUsername, "username must match %v", dfns.UsernameRegexp.String())
	}
	usr, err := a.getUserByUsername(ctx, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user 2FA state for username %v", username)
	}
	if err = a.checkIfEnough2FAProvided(usr, codes); err != nil {
		return nil, err //nolint:wrapcheck // tErr.
	}
	var rollbackCodes map[TwoFAOptionWithAddr]string
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

func (a *accounts) SecurePaymentConfirmation(ctx context.Context, userID, network, walletId string, body map[string]any) (tmplData any, err error) {
	return a.delegatedRPClient.SecurePaymentConfirmation(ctx, userID, network, walletId, body)
}

// TODO: embed in proxy, but how to detect network??
func (a *accounts) Broadcast(ctx context.Context, userID, walletId, txBody string) (response *BroadcastTxResponse, err error) {
	usr, err := a.getUserByID(ctx, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by id %v", userID)
	}
	return a.delegatedRPClient.Broadcast(ctx, userID, walletId, usr.MasterPubKey, txBody)
}
