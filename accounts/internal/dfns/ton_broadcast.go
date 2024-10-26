// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	stdlibtime "time"

	"github.com/pkg/errors"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"

	"github.com/ice-blockchain/wintr/log"
)

func parseTONTransaction(encodedTx []byte, parsedPayment *transferTransaction) (*tonTransactionInputV4R2, error) {
	txCell, err := cell.FromBOC(encodedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cell from transaction bytes: %w", err)
	}
	var tx tonTransactionInputV4R2
	err = tlb.LoadFromCell(&tx, txCell.BeginParse())
	if err != nil {
		return nil, fmt.Errorf("failed to load transaction from cell: %w", err)
	}
	if parsedPayment != nil {
		*parsedPayment = transferTransaction{
			ReceiverAddress: tx.InternalMessage.DestAddr().Bounce(false).String(),
			Amount:          tx.InternalMessage.Amount.String(),
			Network: &network{
				Currency: "TON",
				Icon:     "https://ton.org/download/ton_symbol.png",
			},
		}
	}

	return &tx, nil
}

func (c *dfnsClient) issueUserSignatureForTransaction(ctx context.Context, walletID string, txPayload string) (*signatureResult, error) {
	header := http.Header{}
	header.Set(appIDHeader, appID(ctx))
	header.Set(authDfnsHeader, dfnsAuthHeader(ctx))
	header.Set(userActionDfnsHeader, dfnsUserActionHeader(ctx))
	resp, err := dfnsCall[struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	}, signatureResult](ctx, c, struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	}{Kind: "Message", Message: txPayload}, "POST", fmt.Sprintf("/wallets/%v/signatures", walletID), header)

	return resp, errors.Wrapf(err, "failed to issue tx signature for manual ton broadcasting")
}

func mustInitTONClient(ctx context.Context, configUrl string) ton.APIClientWrapped {
	client := liteclient.NewConnectionPool()
	err := client.AddConnectionsFromConfigUrl(ctx, configUrl)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to fetch config from %v", configUrl))
	}
	api := ton.NewAPIClient(client).WithRetry(10)

	return api
}

func (c *dfnsClient) broadcastTONTransaction(ctx context.Context, userID, walletID, walletPubkey string, txPayload string) (*BroadcastTxResponse, error) {
	signature, err := c.issueUserSignatureForTransaction(ctx, walletID, txPayload)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to issue tx signature for manual tx broadcasting")
	}
	if signature.Signature.Encoded == "" {
		signature.Signature.Encoded = strings.TrimPrefix(signature.Signature.R, "0x") + strings.TrimPrefix(signature.Signature.S, "0x")
	}
	txPayloadBytes, err := hex.DecodeString(txPayload)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode tx payload, invalid hex %v", txPayloadBytes)
	}
	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(signature.Signature.Encoded, "0x"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode signature, invalid hex %v", signature.Signature.Encoded)
	}
	walletPubkeyBytes, err := hex.DecodeString(walletPubkey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode wallet pub key, invalid hex %v", walletPubkey)
	}
	var signedTxCell *tlb.ExternalMessage
	signedTxCell, err = c.embedSignature(ctx, txPayloadBytes, signatureBytes, walletPubkeyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to embed tx signature %v into tx %v", signature.Signature.Encoded, txPayload)
	}

	tx, _, _, err := c.tonApi.SendExternalMessageWaitTransaction(ctx, signedTxCell)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to broadcast tx")
	}

	return buildDfnsBroadcastResp(ctx, signature.ID, userID, walletID, signedTxCell.Body.ToBOCWithFlags(false), tx.Hash), nil
}

func (d *dfnsClient) embedSignature(ctx context.Context, txPayload, signature []byte, walletPubkey []byte) (*tlb.ExternalMessage, error) {
	decodedTx, err := parseTONTransaction(txPayload, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode tx payload, invalid tx body")
	}

	block, err := d.tonApi.CurrentMasterchainInfo(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block")
	}
	addr, err := wallet.AddressFromPubKey(walletPubkey, wallet.V4R2, decodedTx.WalletID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build wallet addr from pub key %v", walletPubkey)
	}
	acc, err := d.tonApi.WaitForBlock(block.SeqNo).GetAccount(ctx, block, addr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get account state %v", addr.String())
	}

	initialized := acc.IsActive && acc.State.Status == tlb.AccountStatusActive
	seqNo, err := d.reqSeqno(ctx, block, addr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get seqNo")
	}
	if seqNo <= decodedTx.Seq {
		return nil, errors.Wrapf(ErrRaceCondition, "invalid seqNo %v actual is %v", decodedTx.Seq, seqNo)
	}
	msg, err := decodedTx.embedSignature(signature, walletPubkey, addr, initialized)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to embed signature")
	}

	return msg, nil
}

func (d *dfnsClient) reqSeqno(ctx context.Context, block *ton.BlockIDExt, addr *address.Address) (uint64, error) {
	resp, err := d.tonApi.WaitForBlock(block.SeqNo).RunGetMethod(ctx, block, addr, "seqno")
	if err != nil {
		if cErr, ok := err.(ton.ContractExecError); ok && cErr.Code == ton.ErrCodeContractNotInitialized {
			return 0, nil
		}
		return 0, fmt.Errorf("get seqno err: %w", err)
	}

	iSeq, err := resp.Int(0)
	if err != nil {
		return 0, fmt.Errorf("failed to parse seqno: %w", err)
	}
	return iSeq.Uint64(), nil
}

func (r *tonTransactionInputV4R2) embedSignature(signature, walletPubkey []byte, addr *address.Address, initialized bool) (*tlb.ExternalMessage, error) {
	payload := cell.BeginCell().MustStoreUInt(uint64(r.WalletID), 32).
		MustStoreUInt(r.TTL, 32).
		MustStoreUInt(r.Seq, 32).
		MustStoreInt(0, 8) // op

	intMsg, err := tlb.ToCell(r.InternalMessage)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert internal message %v", r.InternalMessage)
	}

	payload.MustStoreUInt(uint64(r.Mode), 8).MustStoreRef(intMsg)

	msg := cell.BeginCell().MustStoreSlice(signature, 512).MustStoreBuilder(payload).EndCell()
	var init *tlb.StateInit
	if !initialized {
		init, err = wallet.GetStateInit(walletPubkey, wallet.V4R2, r.WalletID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get init state")
		}
	}
	return &tlb.ExternalMessage{
		DstAddr:   addr,
		StateInit: init,
		Body:      msg,
	}, nil
}

func buildDfnsBroadcastResp(ctx context.Context, signatureID, userID, walletID string, txBody, txHash []byte) *BroadcastTxResponse {
	return &BroadcastTxResponse{
		Id:       signatureID,
		WalletId: walletID,
		Network:  "Ton",
		Requester: struct {
			UserId string `json:"userId"`
			AppId  string `json:"appId"`
		}{
			UserId: userID,
			AppId:  appID(ctx),
		},
		RequestBody: struct {
			Kind        string `json:"kind"`
			Transaction string `json:"transaction"`
		}{
			Kind:        "Transaction",
			Transaction: hex.EncodeToString(txBody),
		},
		Status:          "Broadcasted",
		TxHash:          base64.StdEncoding.EncodeToString(txHash),
		DateRequested:   stdlibtime.Now(),
		DateBroadcasted: stdlibtime.Now(),
	}
}

func (c *dfnsClient) Broadcast(ctx context.Context, userID, walletID, walletPubkey, txPayload string) (*BroadcastTxResponse, error) {
	return c.broadcastTONTransaction(ctx, userID, walletID, walletPubkey, txPayload)
}
