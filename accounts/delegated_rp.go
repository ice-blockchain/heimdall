// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (a *accounts) ProxyDelegatedRelyingParty(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	a.delegatedRPClient.ProxyCall(ctx, rw, r)
}

func (a *accounts) StartDelegatedRecovery(ctx context.Context, username, credentialID string, codes map[TwoFAOptionWithAddr]string) (*StartedDelegatedRecovery, error) {
	username = strings.ToLower(username)
	if !dfns.UsernameRegexp.MatchString(username) {
		return nil, errors.Wrapf(dfns.ErrInvalidUsername, "username must match %v", dfns.UsernameRegexp.String())
	}
	usr, err := a.getUserByIdentityKeyName(ctx, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user 2FA state for username %v", username)
	}
	var delegatedResp *StartedDelegatedRecovery
	delegatedResp, err = a.delegatedRPClient.StartDelegatedRecovery(ctx, username, credentialID)
	if err != nil {
		return nil, multierror.Append(
			errors.Wrapf(err, "failed to start delegated recovery for username %v", username),
		)
	}
	var hasEnabled2FA bool
	if hasEnabled2FA, err = a.checkIfEnough2FAProvided(usr, codes); err != nil {
		return nil, err //nolint:wrapcheck // tErr.
	}
	if hasEnabled2FA {
		if _, err = a.verifyAndRedeem2FA(ctx, usr.ID, codes); err != nil {
			return nil, errors.Wrapf(err, "failed to verify 2FA codes")
		}
	}
	return delegatedResp, nil
}

func (a *accounts) GetLoginChallenge(ctx context.Context, username string, codes map[TwoFAOptionWithAddr]string) (*LoginChallenge, error) {
	username = strings.ToLower(username)
	if username != "" && !dfns.UsernameRegexp.MatchString(username) {
		return nil, errors.Wrapf(dfns.ErrInvalidUsername, "username must match %v", dfns.UsernameRegexp.String())
	}
	var usr *user
	var uErr error
	if username != "" { // Client passes empty username for autocomplete
		usr, uErr = a.getUserByIdentityKeyName(ctx, username)
		if uErr != nil && storage.IsErr(uErr, storage.ErrNotFound) {
			return nil, &dfns.DfnsInternalError{
				Context:    nil,
				Message:    "Unauthorized",
				HTTPStatus: 401,
			}
		}
	}
	loginChallenge, err := a.delegatedRPClient.GetLoginChallenge(ctx, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to initiate login for username %v", username)
	}
	if loginChallenge.PasswordLogin() {
		if username == "" {
			return nil, errors.Wrapf(ErrInvalidIdentityKey, "password flow is unsupported without username, use passkey")
		}
		if uErr != nil && !errors.Is(uErr, storage.ErrNotFound) {
			return nil, errors.Wrapf(uErr, "failed to get user for username %v", username)
		}
		if usr != nil {
			var hasEnabled2FA bool
			if hasEnabled2FA, err = a.checkIfEnough2FAProvided(usr, codes); err != nil {
				return nil, err //nolint:wrapcheck // tErr.
			}
			if hasEnabled2FA {
				if _, err = a.verifyAndRedeem2FA(ctx, usr.ID, codes); err != nil {
					return nil, errors.Wrapf(err, "failed to verify 2FA codes")
				}
			}
		}
	}
	return loginChallenge, nil
}

func (a *accounts) SecurePaymentConfirmation(ctx context.Context, userID, walletId string, body map[string]string) (tmplData any, err error) {
	wallet, err := a.delegatedRPClient.GetWallet(ctx, walletId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get wallet %v, cannot init payment confirmation", walletId)
	}
	_, network, _ := dfns.ExtractWallet(*wallet)

	return a.delegatedRPClient.SecurePaymentConfirmation(ctx, userID, strings.ToLower(network), *wallet, body)
}
