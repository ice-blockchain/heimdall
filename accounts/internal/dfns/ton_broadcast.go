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

func parseTONTransaction(encodedTx []byte, parsedPayment *transferTransaction) (tonTx, error) {
	txCell, err := cell.FromBOC(encodedTx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse cell from transaction bytes")
	}
	var tx tonTransactionInputV4R2
	err = tlb.LoadFromCell(&tx, txCell.BeginParse())
	if err != nil {
		var txV5 tonTransactionInputV5
		err = tlb.LoadFromCell(&txV5, txCell.BeginParse())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load transaction input")
		}
		if parsedPayment != nil {
			*parsedPayment = transferTransaction{
				ReceiverAddress: (*txV5.Actions)[0].Msg.DestAddr().Bounce(false).String(),
				Amount:          (*txV5.Actions)[0].Msg.Amount.String(),
				Network: &network{
					NativeToken: "TON",
					Icon:        "https://ton.org/download/ton_symbol.png",
				},
			}
		}
		return &txV5, nil
	}
	if parsedPayment != nil {
		*parsedPayment = transferTransaction{
			ReceiverAddress: tx.InternalMessage.DestAddr().Bounce(false).String(),
			Amount:          tx.InternalMessage.Amount.String(),
			Network: &network{
				NativeToken: "TON",
				Icon:        "https://ton.org/download/ton_symbol.png",
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
	}, signatureResult](ctx, c, &struct {
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

func (c *dfnsClient) broadcastTONTransaction(ctx context.Context, walletID, walletPubkey string, txPayload string) (*BroadcastTxResponse, error) {
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

	return buildDfnsBroadcastResp(ctx, signature.ID, signature.Requester.UserID, walletID, signedTxCell.Body.ToBOCWithFlags(false), tx.Hash), nil
}

func (d *dfnsClient) embedSignature(ctx context.Context, txPayload, signature []byte, walletPubkey []byte) (*tlb.ExternalMessage, error) {
	decodedTx, err := parseTONTransaction(txPayload, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode tx payload, invalid tx body")
	}
	var ver wallet.VersionConfig
	switch decodedTx.(type) {
	case *tonTransactionInputV4R2:
		ver = wallet.V4R2
	case *tonTransactionInputV5:
		networkID := int32(wallet.MainnetGlobalID)
		if d.cfg.DFNS.TestNet {
			networkID = int32(wallet.TestnetGlobalID)
		}
		ver = wallet.ConfigV5R1Final{
			NetworkGlobalID: networkID,
			Workchain:       0,
		}
	}
	block, err := d.tonApi.CurrentMasterchainInfo(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get block")
	}
	addr, err := wallet.AddressFromPubKey(walletPubkey, ver, decodedTx.GetWalletID())
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
	if seqNo > decodedTx.GetSeq() {
		return nil, errors.Wrapf(ErrRaceCondition, "invalid seqNo %v actual is %v", decodedTx.GetSeq(), seqNo)
	}
	networkID := int32(wallet.MainnetGlobalID)
	if d.cfg.DFNS.TestNet {
		networkID = int32(wallet.TestnetGlobalID)
	}
	msg, _, err := decodedTx.EmbedSignature(signature, walletPubkey, initialized, networkID)
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

func (r *tonTransactionInputV4R2) EmbedSignature(signature, walletPubkey []byte, initialized bool, networkID int32) (*tlb.ExternalMessage, *cell.Cell, error) {
	addr, err := wallet.AddressFromPubKey(walletPubkey, wallet.V4R2, r.WalletID)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to build wallet addr from pub key %v", walletPubkey)
	}
	payload := cell.BeginCell().MustStoreUInt(uint64(r.WalletID), 32).
		MustStoreUInt(r.TTL, 32).
		MustStoreUInt(r.Seq, 32).
		MustStoreInt(0, 8) // op

	intMsg, err := tlb.ToCell(r.InternalMessage)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to convert internal message %v", r.InternalMessage)
	}

	payload.MustStoreUInt(uint64(r.Mode), 8).MustStoreRef(intMsg)

	msg := cell.BeginCell().MustStoreSlice(signature, 512).MustStoreBuilder(payload).EndCell()
	var init *tlb.StateInit
	if !initialized {
		init, err = wallet.GetStateInit(walletPubkey, wallet.V4R2, r.WalletID)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to get init state")
		}
	}
	return &tlb.ExternalMessage{
		DstAddr:   addr,
		StateInit: init,
		Body:      msg,
	}, payload.EndCell(), nil
}
func (r *tonTransactionInputV5) EmbedSignature(signature, walletPubkey []byte, initialized bool, networkID int32) (*tlb.ExternalMessage, *cell.Cell, error) {
	addr, err := wallet.AddressFromPubKey(walletPubkey, wallet.ConfigV5R1Final{NetworkGlobalID: wallet.TestnetGlobalID}, 0)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to build wallet addr from pub key %v", walletPubkey)
	}
	var list = cell.BeginCell().EndCell()
	for _, message := range *r.Actions {
		outMsg, err := tlb.ToCell(message.Msg)
		if err != nil {
			return nil, nil, err
		}
		msg := cell.BeginCell().MustStoreUInt(0x0ec3c86d, 32). // action_send_msg prefix
									MustStoreUInt(uint64(message.Mode), 8). // mode
									MustStoreRef(outMsg)                    // message reference

		list = cell.BeginCell().MustStoreRef(list).MustStoreBuilder(msg).EndCell()
		fmt.Println(list.Dump(100))
	}
	act := cell.BeginCell().MustStoreUInt(1, 1).MustStoreRef(list).MustStoreUInt(0, 1)

	payload := cell.BeginCell().
		MustStoreUInt(0x7369676e, 32).         // external sign op code
		MustStoreUInt(uint64(r.WalletID), 32). // serialized WalletId
		MustStoreUInt(uint64(r.TTL), 32).      // validUntil
		MustStoreUInt(uint64(r.Seq), 32).      // seq (block)
		MustStoreBuilder(act)                  // Action list
	fmt.Println("PL:", hex.EncodeToString(payload.EndCell().ToBOC()))
	fmt.Println("PLHASH:", payload.EndCell().Dump(100))
	var init *tlb.StateInit
	if !initialized {
		init, err = wallet.GetStateInit(walletPubkey, wallet.ConfigV5R1Final{
			NetworkGlobalID: networkID,
		}, 0)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to get init state")
		}
	}

	return &tlb.ExternalMessage{
		DstAddr:   addr,
		StateInit: init,
		Body:      cell.BeginCell().MustStoreBuilder(payload).MustStoreSlice(signature, 512).EndCell(),
	}, payload.EndCell(), nil
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

func (a *v5actions) LoadFromCell(loader *cell.Slice) error {
	if a == nil {
		a = new(v5actions)
	}
	var actions []v5action
	for {
		switch loader.BitsLeft() {
		case 0:
			*a = actions
			return nil
		case 40:
			next, err := loader.LoadRef()
			if err != nil {
				return err
			}
			var action v5action
			if err := tlb.LoadFromCell(&action, loader); err != nil {
				return err
			}
			actions = append(actions, action)
			loader = next
		default:
			return fmt.Errorf("unexpected bits available: %v", loader.BitsLeft())
		}
	}
}

func (t *tonTransactionInputV4R2) GetWalletID() uint32 {
	return t.WalletID
}
func (t *tonTransactionInputV4R2) GetSeq() uint64 {
	return uint64(t.Seq)
}
func (t *tonTransactionInputV5) GetWalletID() uint32 {
	return t.WalletID
}
func (t *tonTransactionInputV5) GetSeq() uint64 {
	return uint64(t.Seq)
}
