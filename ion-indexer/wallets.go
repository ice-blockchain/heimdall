// SPDX-License-Identifier: ice License 1.0

package ion_indexer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/xssnick/tonutils-go/address"

	"github.com/ice-blockchain/wintr/log"
)

func (i *indexer) WalletTransactions(ctx context.Context, walletId, walletAddr string, paginationToken string, limit uint64) ([]WalletHistoryItem, *string, error) {
	if paginationToken == "" {
		paginationToken = "0" // Basically offset, but on 3rd party wallet provider they use strings, we try to mimic to their endpoint
	}
	offset, err := strconv.ParseUint(paginationToken, 10, 64)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse pagination token: %v", paginationToken)
	}
	txs, newPagination, err := i.listTransactions(ctx, walletId, walletAddr, offset, limit)
	return txs, newPagination, errors.Wrapf(err, "failed to fetch wallet history for wallet %v from ion indexer", walletAddr)
}

func (i *indexer) listTransactions(ctx context.Context, walletId, walletAddress string, offset, limit uint64) ([]WalletHistoryItem, *string, error) {
	params := map[string]string{
		"offset":  fmt.Sprintf("%v", offset),
		"account": walletAddress,
		"sort":    "desc",
	}
	if limit < defaultIndexerReqLimit {
		params["limit"] = fmt.Sprintf("%v", limit)
	}
	total := uint64(0)
	txs, newOffset, err := indexerReq[WalletHistoryItem](ctx, i, "/indexer/v3/transactions", params, func(data []byte) ([]WalletHistoryItem, bool, error) {
		var transactions getTransactionsIndexerResponse
		if err := json.UnmarshalContext(ctx, data, &transactions); err != nil {
			return nil, false, err
		}
		res := []WalletHistoryItem{}
		var wg sync.WaitGroup
		type txHashWithExtHash struct {
			txHash         string
			txExternalHash string
		}
		updatedExternalHashes := make(chan txHashWithExtHash, len(transactions.Transactions))
		for _, tx := range transactions.Transactions {
			network := "Ion"
			if i.testnet {
				network = "IonTestnet"
			}
			history, err := tx.ToHistory(network, walletId, walletAddress)
			if err != nil {
				return nil, false, errors.Wrapf(err, "failed to convert tx %+v to history item", tx)
			}
			// Incoming txs dont have in_msg hash matching sent BoC (diff msgs for sender & receiver),
			// but FE needs that for linking pending and completed txs
			if history["direction"] == "In" {
				wg.Go(func() {
					fullTx, err := i.TxByHash(ctx, history["txHash"].(string), network, walletId, walletAddress)
					if err != nil {
						log.Error(errors.Wrapf(err, "failed to fetch tx by hash %v from ion indexer", tx.Hash))
						return
					}
					incomingMessageHash, err := base64.StdEncoding.DecodeString(fullTx.InMsg.Hash)
					if err != nil {
						log.Error(errors.Wrapf(err, "malformed tx from indexer, failed to decode in msg hash %v", tx.Hash))
						return
					}
					updatedExternalHashes <- txHashWithExtHash{
						txHash:         history["txHash"].(string),
						txExternalHash: hex.EncodeToString(incomingMessageHash),
					}
				})
			}
			res = append(res, history)
		}
		wg.Wait()
		close(updatedExternalHashes)
		for updExternalHash := range updatedExternalHashes {
			for historyIdx := range res {
				if res[historyIdx]["txHash"] == updExternalHash.txHash {
					r := res[historyIdx]
					r["externalHash"] = updExternalHash.txExternalHash
					res[historyIdx] = r
					break
				}
			}
		}
		continuePagination := true
		total += uint64(len(res))
		if uint64(len(res)) < defaultIndexerReqLimit || total >= limit {
			continuePagination = false
		}
		return res, continuePagination, nil
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to fetch wallet history from ion indexer for wallet %v", walletAddress)
	}
	if uint64(len(txs)) >= limit {
		paginationToken := fmt.Sprintf("%v", newOffset)
		return txs, &paginationToken, nil
	}
	return txs, nil, nil
}

func (i *indexer) TxByHash(ctx context.Context, txHash, network, walletId, walletAddress string) (*transaction, error) {
	params := map[string]string{
		"hash": txHash,
	}
	tx, _, err := indexerReq[transaction](ctx, i, "/indexer/v3/transactions", params, func(data []byte) ([]transaction, bool, error) {
		var transactions getTransactionsIndexerResponse
		if err := json.UnmarshalContext(ctx, data, &transactions); err != nil {
			return nil, false, err
		}
		if len(transactions.Transactions) == 0 {
			return nil, false, errors.Errorf("tx %v not found", txHash)
		}
		return transactions.Transactions, false, nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch tx %v by hash from ion indexer", txHash)
	}
	return &tx[0], nil
}

func (tx transaction) ToHistory(network, walletId, walletAddress string) (WalletHistoryItem, error) {
	txHash, err := base64.StdEncoding.DecodeString(tx.Hash)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed tx from indexer, failed to decode tx hash %v", tx.Hash)
	}
	traceId, err := base64.StdEncoding.DecodeString(tx.TraceId)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed tx from indexer, failed to decode tx trace_id %v", tx.TraceId)
	}
	incomingMessageHash, err := base64.StdEncoding.DecodeString(tx.InMsg.Hash)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed tx from indexer, failed to decode in msg hash %v", tx.Hash)
	}
	destMsg := tx.InMsg
	if len(tx.OutMsgs) >= 1 {
		destMsg = tx.OutMsgs[0]
	}
	addr, err := address.ParseAddr(walletAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse wallet address %q for wallet %q", walletAddress, walletId)
	}
	direction := "Out"
	if strings.EqualFold(destMsg.Destination, addr.StringRaw()) {
		direction = "In"
	}
	var sourceAddr *address.Address
	if tx.InMsg.Source == "" {
		sourceAddr = addr
	} else {
		sourceAddr, err = address.ParseRawAddr(tx.InMsg.Source)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse wallet address %q for tx %v", tx.InMsg.Source, "0x"+hex.EncodeToString(txHash))
	}
	destAddr, err := address.ParseRawAddr(destMsg.Destination)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse wallet address %q for tx %v", destMsg.Destination, "0x"+hex.EncodeToString(txHash))
	}

	return WalletHistoryItem(map[string]any{
		"kind":         "NativeTransfer",
		"walletId":     walletId,
		"network":      network,
		"direction":    direction,
		"blockNumber":  tx.BlockRef.Seqno,
		"timestamp":    time.Unix(tx.Now, 0).Format(time.RFC3339),
		"txHash":       hex.EncodeToString(traceId),
		"externalHash": hex.EncodeToString(incomingMessageHash),
		"index":        hex.EncodeToString(txHash),
		"from":         sourceAddr.Bounce(false).String(),
		"to":           destAddr.Bounce(false).String(),
		"value":        destMsg.Value,
		"decimals":     9,
		"fee":          tx.TotalFees,
		"symbol":       "ION",
		"metadata": map[string]any{
			"asset": map[string]any{
				"symbol":   "ION",
				"decimals": 9,
				"verified": true,
			},
			"fee": map[string]any{
				"symbol":   "ION",
				"decimals": 9,
				"verified": true,
			},
		},
	}), nil
}

func (i *indexer) GetBalance(ctx context.Context, walletAddress string) ([]Asset, error) {
	params := map[string]string{
		"address": walletAddress,
	}
	nativeAsset, _, err := indexerReq[Asset](ctx, i, "/indexer/v3/accountStates", params, func(data []byte) ([]Asset, bool, error) {
		var accountStateResp accountStateResponse
		if err := json.UnmarshalContext(ctx, data, &accountStateResp); err != nil {
			return nil, false, err
		}
		if len(accountStateResp.Accounts) == 0 {
			return []Asset{Asset(map[string]any{
				"kind":     "Native",
				"decimals": 9,
				"balance":  "0",
				"symbol":   "ION",
				"verified": true,
			})}, false, nil
		}
		return []Asset{Asset(map[string]any{
			"kind":     "Native",
			"decimals": 9,
			"balance":  accountStateResp.Accounts[0].Balance,
			"symbol":   "ION",
			"verified": true,
		})}, false, nil
	})
	return nativeAsset, errors.Wrapf(err, "failed to fetch balance of wallet %v from indexer", walletAddress)
}
