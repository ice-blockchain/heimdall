// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
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

func decodeBody(ctx context.Context, body io.Reader) (map[string]any, error) {
	respData, err := io.ReadAll(body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read delegated relying party body")
	}
	var res map[string]any
	if err = json.UnmarshalContext(ctx, respData, &res); err != nil {
		return nil, errors.Wrapf(err, "failed to parse json for %v", string(respData))
	}
	return res, nil
}

func extractWalletPubKey(res map[string]any) (walletPubKey string) {
	if walletsI, hasWallets := res["wallets"]; hasWallets {
		wallets := walletsI.([]any)
		for _, walletI := range wallets {
			if walletI != nil {
				wallet := walletI.(map[string]any)
				if nameI, hasName := wallet["name"]; hasName && nameI != nil {
					if name, ok := nameI.(string); !ok || name != dfns.DefaultWalletName {
						continue
					}
				}
				if networkI, hasNetwork := wallet["network"]; hasNetwork && networkI != nil {
					if network, ok := networkI.(string); !ok || network != dfns.DefaultWalletNetwork {
						continue
					}
				}
				if keyI, hasKey := wallet["signingKey"]; hasKey && keyI != nil {
					key := keyI.(map[string]any)
					if pubkey, hasPk := key["publicKey"]; hasPk {
						walletPubKey = pubkey.(string)
					}
				}
			}
		}
	}
	return walletPubKey
}

func extractUser(res map[string]any, usernameField string) (userID, username string) {
	var usr map[string]any
	if userInferface, hasUser := res["user"]; hasUser {
		usr = userInferface.(map[string]any)
	}
	if len(usr) == 0 {
		return "", ""
	}
	userID = usr["id"].(string)
	username = usr[usernameField].(string)
	return
}
