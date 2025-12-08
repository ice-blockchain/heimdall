// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

func ExtractUser(res map[string]any, usernameField string) (userID, identityKeyName string) {
	var usr map[string]any
	if userInferface, hasUser := res["user"]; hasUser {
		usr = userInferface.(map[string]any)
	}
	if len(usr) == 0 {
		return "", ""
	}
	userID = usr["id"].(string)
	identityKeyName = strings.ToLower(usr[usernameField].(string))
	return
}

func ExtractMainWallet(res map[string]any) (walletID, walletPubKey string) {
	if walletsI, hasWallets := res["wallets"]; hasWallets {
		wallets := walletsI.([]any)
		for _, walletI := range wallets {
			if walletI != nil {
				wallet := walletI.(map[string]any)
				if walletID, walletPubKey = CheckMainWallet(wallet); walletID == "" && walletPubKey == "" {
					continue
				}
			}
		}
	}
	return walletID, walletPubKey
}

func CheckMainWallet(wallet Wallet, networks ...string) (walletID, walletPubKey string) {
	if len(networks) == 0 {
		networks = []string{DefaultWalletNetworkTestNet, DefaultWalletNetworkMainNet}
	}
	if nameI, hasName := wallet["name"]; hasName && nameI != nil {
		if name, ok := nameI.(string); !ok || name != defaultWalletName {
			return "", ""
		}
	}
	if networkI, hasNetwork := wallet["network"]; hasNetwork && networkI != nil {
		if network, ok := networkI.(string); !ok || !slices.Contains(networks, network) {
			return "", ""
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
	return walletID, walletPubKey
}

func ExtractWallet(wallet Wallet) (walletID, network, walletPubKey string) {
	if idI, hasID := wallet["id"]; hasID && idI != nil {
		walletID = idI.(string)
	}
	if networkI, hasNetwork := wallet["network"]; hasNetwork && networkI != nil {
		network = networkI.(string)
	}
	if keyI, hasKey := wallet["signingKey"]; hasKey && keyI != nil {
		key := keyI.(map[string]any)
		if pubkey, hasPk := key["publicKey"]; hasPk {
			walletPubKey = pubkey.(string)
		}
	}
	return walletID, network, walletPubKey
}

func (c *dfnsClient) GetUser(ctx context.Context, userID string) (*User, error) {
	headers := http.Header{}
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

func (c *dfnsClient) CompleteRegistrationWithWallets(ctx context.Context, credentials *Credentials) (CompletedRegistration, error) {
	header := http.Header{}
	header.Add(authDfnsHeader, dfnsAuthHeader(ctx))
	header.Add(userActionDfnsHeader, "false")
	credentials.EarlyAccessEmail = ""
	walletNetwork := DefaultWalletNetworkMainNet
	bscNetwork := BscWalletNetworkMainNet
	if c.cfg.DFNS.TestNet {
		walletNetwork = DefaultWalletNetworkTestNet
		bscNetwork = BscWalletNetworkTestNet
	}
	credentials.Wallets = []struct {
		Network string `json:"network"`
		Name    string `json:"name"`
	}{{Network: walletNetwork, Name: defaultWalletName}, {Network: bscNetwork, Name: defaultWalletName + "-bsc"}}
	resp, err := dfnsCall[Credentials, map[string]any](ctx, c, credentials, "POST", "/auth/registration/enduser", header)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to finish registration due to failed dfns call")
	}
	userID, username := ExtractUser(*resp, "username")
	err = c.extendRegistrationBodyWithRefreshToken(userID, username)(ctx, *resp)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to issue refresh token for user %v %v", userID, username)
	}
	err = extendResponseBodyWithPaymentExtension()(ctx, *resp)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to enable payment extension for %v %v", userID, username)
	}
	return *resp, nil
}
