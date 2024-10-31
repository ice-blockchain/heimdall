// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"fmt"
	"net/http"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

func ExtractUser(res map[string]any, usernameField string) (userID, username string) {
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

func ExtractWalletPubKey(res map[string]any) (walletID, walletPubKey string) {
	if walletsI, hasWallets := res["wallets"]; hasWallets {
		wallets := walletsI.([]any)
		for _, walletI := range wallets {
			if walletI != nil {
				wallet := walletI.(map[string]any)
				if nameI, hasName := wallet["name"]; hasName && nameI != nil {
					if name, ok := nameI.(string); !ok || name != defaultWalletName {
						continue
					}
				}
				if networkI, hasNetwork := wallet["network"]; hasNetwork && networkI != nil {
					if network, ok := networkI.(string); !ok || network != defaultWalletNetwork {
						continue
					}
				}
				if keyI, hasKey := wallet["signingKey"]; hasKey && keyI != nil {
					key := keyI.(map[string]any)
					if pubkey, hasPk := key["publicKey"]; hasPk {
						walletPubKey = pubkey.(string)
					}
				}
				if idI, hasID := wallet["id"]; hasID && idI != nil {
					walletID = idI.(string)
				}
			}
		}
	}
	return walletID, walletPubKey
}

func (c *dfnsClient) GetUser(ctx context.Context, userID string) (*User, error) {
	headers := http.Header{}
	headers.Set(appIDHeader, appID(ctx))
	uri := fmt.Sprintf("/auth/users/%v", userID)
	status, body, err := c.clientCall(ctx, "GET", uri, headers, nil)
	if status >= http.StatusBadRequest && err == nil {
		err = buildDfnsError(status, uri, body)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user %v from dfns", userID)
	}
	var usr User
	if err = json.UnmarshalContext(ctx, body, &usr); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response %v for to User", string(body))
	}
	return &usr, nil
}
