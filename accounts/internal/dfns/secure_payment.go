package dfns

import (
	"context"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"net/http"
)

func (c *dfnsClient) requestUserActionChallenge(ctx context.Context, url string, method string, payload map[string]any) (*signatureChallenge, error) {
	header := http.Header{}
	header.Set(appIDHeader, appID(ctx))
	header.Set(authDfnsHeader, dfnsAuthHeader(ctx))
	header.Set(userActionDfnsHeader, "false")
	signablePayload, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to serialize signable payload %#v", payload)
	}
	resp, err := dfnsCall[struct {
		UserActionPayload    string `json:"userActionPayload"`
		UserActionHTTPMethod string `json:"userActionHttpMethod"`
		UserActionHTTPPath   string `json:"userActionHttpPath"`
		UserActionServerKind string `json:"userActionServerKind"`
	}, signatureChallenge](ctx, c, struct {
		UserActionPayload    string `json:"userActionPayload"`
		UserActionHTTPMethod string `json:"userActionHttpMethod"`
		UserActionHTTPPath   string `json:"userActionHttpPath"`
		UserActionServerKind string `json:"userActionServerKind"`
	}{UserActionPayload: string(signablePayload), UserActionHTTPMethod: method, UserActionHTTPPath: url, UserActionServerKind: "Api"}, "POST", "/auth/action/init", header)
	return resp, errors.Wrapf(err, "failed to get user action challenge")
}

func (c *dfnsClient) SecurePaymentConfirmation(ctx context.Context, userID, network, walletId string, body map[string]any) (any, error) {
	transaction, err := c.extractTransaction(network, walletId, body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to extract transaction details")
	}
	ch, err := c.requestUserActionChallenge(ctx, fmt.Sprintf("/wallets/%v/transactions/", walletId), "POST", body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to request user action challenge for SPC over wallet %v", walletId)
	}
	challenge := *ch
	if err = c.extendChallengeWithPaymentInfo(challenge, transaction); err != nil {
		return nil, errors.Wrapf(err, "failed to extend challenge with payment info")
	}
	return struct {
		Tx        *tx
		Challenge map[string]any
		UserID    string
		Token     string
		AppID     string
		Origin    string
	}{
		Tx:        transaction,
		Challenge: challenge,
		UserID:    userID,
		Token:     dfnsAuthHeader(ctx),
		AppID:     c.webFE.AppID,
		Origin:    c.webFE.ExpectedOrigin,
	}, nil
}

func (c *dfnsClient) extractTransaction(network, walletId string, broadcastBody map[string]any) (*tx, error) {
	networkData, err := c.detectNetwork(walletId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to detect network %v")
	}
	value, hasValue := broadcastBody["value"]
	to, hasTo := broadcastBody["to"]
	if hasValue && hasTo { // Evm has them.
		return &tx{
			ReceiverAddress: to.(string),
			Sender:          walletId, // TODO: extract addr from tx
			Amount:          value.(string),
			Network:         networkData,
		}, nil
	}
	encodedTx, hasEncodedTx := broadcastBody["transaction"]
	if !hasEncodedTx {
		return nil, errors.New("missing transaction details in body")
	}
	switch network {
	default:
		return nil, errors.Errorf("unsupported network %v cannot decode tx %v", network, encodedTx)
	}
}

func (c *dfnsClient) detectNetwork(walletId string) (*network, error) {
	// TODO: do we need to detect it by stored wallet?
	// TODO: cdn
	return &network{Currency: "BNB", Icon: "https://static.bnbchain.org/home-ui/static/images/bnb-smart-chain/migrate.png"}, nil
}

func (c *dfnsClient) extendChallengeWithPaymentInfo(challenge signatureChallenge, transaction *tx) error {
	// https://w3c.github.io/secure-payment-confirmation/#authentication-example
	challenge["payeeName"] = transaction.ReceiverAddress
	challenge["payeeOrigin"] = c.webFE.ExpectedOrigin
	challenge["rpId"] = (challenge["rp"].(map[string]any))["id"].(string)
	var instrument map[string]any
	if instrumentI, hasInstrument := challenge["instrument"]; !hasInstrument {
		instrument = make(map[string]any)
	} else {
		instrument = instrumentI.(map[string]any)
	}
	instrument["displayName"] = transaction.Sender
	instrument["icon"] = transaction.Network.Icon
	challenge["instrument"] = instrument
	allowedCreds, hasAllowedCreds := challenge["allowCredentials"]
	if _, hasCredentialIds := challenge["credentialIds"]; !hasCredentialIds {
		credentialIds := make([]string, 0)
		if !hasAllowedCreds {
			return errors.New("need allowCredentials in challnenge to build credentialIds")
		}
		keysI, hasKeys := allowedCreds.(map[string]any)["webauthn"]
		if !hasKeys {
			return errors.New("need webauthn keys in allowCredentials in challnenge to build credentialIds")
		}
		keys := keysI.([]any)
		for _, key := range keys {
			credentialIds = append(credentialIds, key.(map[string]any)["id"].(string))
		}
		challenge["credentialIds"] = credentialIds
	}

	return nil
}
