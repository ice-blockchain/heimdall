// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
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
	}, signatureChallenge](ctx, c, &struct {
		UserActionPayload    string `json:"userActionPayload"`
		UserActionHTTPMethod string `json:"userActionHttpMethod"`
		UserActionHTTPPath   string `json:"userActionHttpPath"`
		UserActionServerKind string `json:"userActionServerKind"`
	}{UserActionPayload: string(signablePayload), UserActionHTTPMethod: method, UserActionHTTPPath: url, UserActionServerKind: "Api"}, "POST", "/auth/action/init", header)
	return resp, errors.Wrapf(err, "failed to get user action challenge")
}

func (c *dfnsClient) SecurePaymentConfirmation(ctx context.Context, userID, network string, wallet Wallet, body map[string]any) (any, error) {
	walletId := wallet["id"].(string)
	transaction, err := c.extractTransaction(network, wallet["name"].(string), body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to extract transaction details")
	}
	signedUrl := fmt.Sprintf("/wallets/%v/transactions", walletId)
	if network == "ton" { // It does not support broadcasting, we issue signature instead and broadcast it from our BE.
		signedUrl = fmt.Sprintf("/wallets/%v/signatures", walletId)
		body["message"] = body["transaction"]
		body["kind"] = "Message"
		delete(body, "transaction")
	}
	ch, err := c.requestUserActionChallenge(ctx, signedUrl, "POST", body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to request user action challenge for SPC over wallet %v", walletId)
	}
	challenge := *ch
	if err = c.extendChallengeWithPaymentInfo(challenge, transaction); err != nil {
		return nil, errors.Wrapf(err, "failed to extend challenge with payment info")
	}
	return struct {
		Tx        *transferTransaction
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
		Origin:    "https://192.168.1.36:8001", //c.webFE.ExpectedOrigin,
	}, nil
}

func (c *dfnsClient) extractTransaction(network, walletName string, broadcastBody map[string]any) (*transferTransaction, error) {
	network = strings.ToLower(network)
	networkData, err := c.detectNetwork(network)
	if err != nil {
		return nil, errors.Wrap(err, "failed to detect network %v")
	}
	value, hasValue := broadcastBody["value"]
	to, hasTo := broadcastBody["to"]
	if hasValue && hasTo { // Evm has them.
		return &transferTransaction{
			ReceiverAddress: to.(string),
			Sender:          walletName,
			Amount:          value.(string),
			Network:         networkData,
		}, nil
	}
	encodedTx, hasEncodedTx := broadcastBody["transaction"]
	if !hasEncodedTx {
		return nil, errors.New("missing transaction details in body")
	}
	if strings.HasPrefix(encodedTx.(string), "0x") {
		encodedTx = strings.TrimPrefix(encodedTx.(string), "0x")
	}
	encodedTxBytes, err := hex.DecodeString(encodedTx.(string))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode transaction")
	}
	switch network {
	case "ton":
		var transaction transferTransaction
		if _, err = parseTONTransaction(encodedTxBytes, &transaction); err != nil {
			return nil, errors.Wrap(err, "failed to parse transaction")
		}
		transaction.Sender = walletName
		return &transaction, nil
	case "polygon", "ethereum", "bsc", "arbitrumone", "avalanchec", "fantomopera":
		var transaction *transferTransaction
		if transaction, err = parseEvmTransactionInput(encodedTxBytes); err != nil {
			return nil, errors.Wrapf(err, "failed to parse transaction for EVM %v: %v", network, encodedTxBytes)
		}
		transaction.Sender = walletName
		return transaction, nil
	case "bitcoin":
		var transaction *transferTransaction
		if transaction, err = parseBitcoinTransactionInput(encodedTxBytes); err != nil {
			return nil, errors.Wrapf(err, "failed to parse transaction for BTC %v: %v", network, encodedTxBytes)
		}
		transaction.Sender = walletName
		return transaction, nil
	default:
		return nil, errors.Errorf("unsupported network %v cannot decode transferTransaction %v", network, encodedTx)
	}
}

func parseEvmTransactionInput(txBytes []byte) (*transferTransaction, error) {
	return nil, errors.Errorf("not impl")
}
func parseBitcoinTransactionInput(txBytes []byte) (*transferTransaction, error) {
	return nil, errors.Errorf("not impl")
}

func (c *dfnsClient) detectNetwork(networkName string) (*network, error) {
	// TODO: cdn
	return &network{Currency: "BNB", Icon: "https://static.bnbchain.org/home-ui/static/images/bnb-smart-chain/migrate.png"}, nil
}

func (c *dfnsClient) extendChallengeWithPaymentInfo(challenge signatureChallenge, transaction *transferTransaction) error {
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
