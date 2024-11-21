// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

func (c *dfnsClient) requestUserActionChallenge(ctx context.Context, url string, method string, payload map[string]string) (*signatureChallenge, error) {
	header := http.Header{}
	header.Set(appIDHeader, c.webFE.AppID)
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

func (c *dfnsClient) SecurePaymentConfirmation(ctx context.Context, userID, network string, wallet Wallet, body map[string]string) (any, error) {
	walletId := wallet["id"].(string)
	transaction, err := c.extractTransaction(network, wallet["address"].(string), body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to extract transaction details")
	}
	signedUrl := fmt.Sprintf("/wallets/%v/transactions", walletId)
	if network == networkTON || network == networkION { // It does not support broadcasting, we issue signature instead and broadcast it from our BE.
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
		Origin:    c.webFE.ExpectedOrigin,
	}, nil
}

func (c *dfnsClient) extractTransaction(network, walletName string, broadcastBody map[string]string) (*transferTransaction, error) {
	network = strings.ToLower(network)
	networkData, err := c.detectNetwork(network)
	if err != nil {
		return nil, errors.Wrap(err, "failed to detect network %v")
	}
	value, hasValue := broadcastBody["value"]
	to, hasTo := broadcastBody["to"]
	if hasValue && hasTo { // Evm has them.
		return &transferTransaction{
			ReceiverAddress: to,
			Sender:          walletName,
			Amount:          value,
			Network:         networkData,
		}, nil
	}
	encodedTx, hasEncodedTx := broadcastBody["transaction"]
	if !hasEncodedTx {
		psbt, hasPbst := broadcastBody["psbt"]
		if !hasPbst {
			return nil, errors.New("missing transaction details in body")
		}
		encodedTx = psbt
	}
	if strings.HasPrefix(encodedTx, "0x") {
		encodedTx = strings.TrimPrefix(encodedTx, "0x")
	}
	encodedTxBytes, err := hex.DecodeString(encodedTx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode transaction")
	}
	switch network {
	case "ton", "tontestnet", "ion", "iontestnet":
		var transaction transferTransaction
		if _, err = parseTONTransaction(encodedTxBytes, &transaction, networkData); err != nil {
			return nil, errors.Wrap(err, "failed to parse transaction")
		}
		transaction.Sender = walletName
		transaction.Amount = networkData.formatDecimals(&transaction)
		return &transaction, nil
	case "polygon", "ethereum", "bsc", "arbitrumone", "avalanchec", "fantomopera", "optimism",
		"ethereumsepolia", "arbitrumsepolia", "avalanchecfuji", "basesepolia", "bsctestnet", "fantomtestnet", "optimismsepolia", "polygonamoy":
		var transaction *transferTransaction
		if transaction, err = c.parseEvmTransactionInput(networkData, encodedTxBytes); err != nil {
			return nil, errors.Wrapf(err, "failed to parse transaction for EVM %v: %v", network, encodedTxBytes)
		}
		transaction.Sender = walletName
		transaction.Amount = networkData.formatDecimals(transaction)
		return transaction, nil
	case "bitcoin", "bitcointestnet3":
		var transaction *transferTransaction
		if transaction, err = parseBitcoinTransactionInput(encodedTxBytes, c.cfg.DFNS.TestNet); err != nil {
			return nil, errors.Wrapf(err, "failed to parse transaction for BTC %v: %v", network, encodedTxBytes)
		}
		transaction.Sender = walletName
		transaction.Amount = networkData.formatDecimals(transaction)
		return transaction, nil
	default:
		return nil, errors.Errorf("unsupported network %v cannot decode transferTransaction %v", network, encodedTx)
	}
}

func (c *dfnsClient) parseEvmTransactionInput(network *network, txBytes []byte) (*transferTransaction, error) {
	var tx types.Transaction

	if err := tx.UnmarshalBinary(txBytes); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal transaction %x", txBytes)
	}
	txDataBytes := tx.Data()
	if len(txDataBytes) == 0 {
		return &transferTransaction{
			ReceiverAddress: tx.To().Hex(),
			Sender:          "",
			Amount:          tx.Value().String(),
			Token:           network.NativeToken,
			Network:         network,
		}, nil
	}
	contractAddress := tx.To().Hex()
	methodSigData := txDataBytes[:4]
	inputsSigData := txDataBytes[4:]
	method, err := c.erc20ABI.MethodById(methodSigData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find method %x in abi", methodSigData)
	}
	inputsMap := make(map[string]interface{})
	if err = method.Inputs.UnpackIntoMap(inputsMap, inputsSigData); err != nil {
		return nil, errors.Wrapf(err, "failed to parse transaction inputs for EVM contract %v: tx %x", contractAddress, txBytes)
	}
	return &transferTransaction{
		ReceiverAddress: inputsMap["receiver"].(string),
		Sender:          "",
		Amount:          inputsMap["amount"].(string),
		Token:           contractAddress,
		Network:         network,
	}, nil
}
func parseBitcoinTransactionInput(txBytes []byte, testnet bool) (*transferTransaction, error) {
	buf := bytes.NewBuffer(txBytes)
	networkCfg := &chaincfg.MainNetParams
	if testnet {
		networkCfg = &chaincfg.TestNet3Params
	}
	btcTx, err := psbt.NewFromRawBytes(buf, false)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse transaction %x", txBytes)
	}
	var senderAddr string
	for _, in := range btcTx.Inputs {
		script, err := txscript.ParsePkScript(in.WitnessUtxo.PkScript)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse wintess input sctipt %x for BTC transaction %x", in.WitnessScript, txBytes)
		}
		address, err := script.Address(networkCfg)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse address from script %x for BTC transaction %x", in.WitnessScript, txBytes)
		}
		senderAddr = address.String()
	}
	transactionValue := big.NewInt(0)
	receiverAddr := ""
	for _, output := range btcTx.UnsignedTx.TxOut {
		script, err := txscript.ParsePkScript(output.PkScript)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse wintess script in output")
		}
		address, err := script.Address(networkCfg)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse address from script %x for BTC transaction %x", output.PkScript, txBytes)
		}
		if address.String() != senderAddr {
			receiverAddr = address.String()
			transactionValue = transactionValue.Add(transactionValue, big.NewInt(output.Value))
		}
	}
	return &transferTransaction{
		ReceiverAddress: receiverAddr,
		Sender:          "",
		Amount:          transactionValue.String(),
		Token:           "BTC",
		Network: &network{
			NativeToken: "BTC",
			Icon:        "",
		},
	}, nil
}

func (c *dfnsClient) detectNetwork(networkName string) (*network, error) {
	switch networkName {
	case "bsctestnet", "bsc":
		return &network{NativeToken: "BNB", Icon: "", decimals: 18}, nil
	case "polygonamoy", "polygon":
		return &network{NativeToken: "MATIC", Icon: "", decimals: 18}, nil
	case "arbitrumsepolia", "arbitrumone":
		return &network{NativeToken: "ARB", Icon: "", decimals: 18}, nil
	case "avalanchec", "avalanchecfuji":
		return &network{NativeToken: "AVAX", Icon: "", decimals: 18}, nil
	case "fantomopera", "fantomtestnet":
		return &network{NativeToken: "FTM", Icon: "", decimals: 18}, nil
	case "ethereumsepolia", "ethereum":
		return &network{NativeToken: "ETH", Icon: "", decimals: 18}, nil
	case "optimism", "optimismsepolia":
		return &network{NativeToken: "OP", Icon: "", decimals: 18}, nil
	case "bitcointestnet3", "bitcoin":
		return &network{NativeToken: "BTC", Icon: "", decimals: 8}, nil
	case networkTON, "tontestnet":
		return &network{NativeToken: "TON", Icon: "https://ton.org/download/ton_symbol.png", decimals: 9}, nil
	case networkION, "iontestnet":
		return &network{NativeToken: "ICE", Icon: "", decimals: 9}, nil
	default:
		return nil, errors.Errorf("unsupported network name %v", networkName)
	}

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
func (n *network) formatDecimals(transaction *transferTransaction) string {
	f, _, err := new(big.Float).Parse(transaction.Amount, 10)
	if err != nil {
		return transaction.Amount
	}
	return new(big.Float).Quo(f, big.NewFloat(math.Pow10(n.decimals))).Text('f', transaction.Network.decimals)
}
