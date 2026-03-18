// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/mitchellh/mapstructure"
	"github.com/nbd-wtf/go-nostr"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/coins"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) VerifyWebhook(ctx context.Context, eventDateTime *time.Time, signature string, payload []byte) error {
	if signature == "" {
		return errors.Wrap(dfns.ErrInvalidToken, "signature is empty")
	}
	if len(payload) == 0 {
		return errors.Wrap(dfns.ErrInvalidToken, "payload is empty")
	}
	now := time.Now()
	return errors.Wrapf(a.delegatedRPClient.VerifyWebhookSecret(now, eventDateTime, signature, payload), "failed to verify wh signature %v", signature)
}

func (a *accounts) ProcessWebhookFromDelegatedRelyingParty(ctx context.Context, kind string, data map[string]any) error {
	return a.processWebhookFromDelegatedRelyingParty(ctx, kind, data, false)
}
func (a *accounts) processWebhookFromDelegatedRelyingParty(ctx context.Context, kind string, data map[string]any, missed bool) error {
	switch kind {
	case webhookTransferConfirmed, webhookTransferBroadcasted, webhookTransferRequested, webhookTransferRejected, webhookTransferFailed:
		var transferReq *webhookTransferRequest = new(webhookTransferRequest)
		if err := mapstructure.Decode(data["transferRequest"], transferReq); err != nil {
			return errors.Wrapf(err, "failed to decode transferRequest payload from webhook %+v", data)
		}
		err := a.enqueueTransferUpsert(ctx, transferReq.WalletID, transferReq.Requester.UserID, transferReq)
		if kind == webhookTransferConfirmed || kind == webhookTransferBroadcasted {
			userID := transferReq.Requester.UserID
			walletID := transferReq.WalletID
			if missed {
				transferReq = nil // dedupl in river
			}
			err = errors.Join(err,
				errors.Wrapf(a.enqueueAssetsUpdate(ctx, walletID, userID, transferReq), "failed to enqueue assets update %v %v from transfer", walletID, userID),
				errors.Wrapf(a.enqueueHistoryUpdate(ctx, walletID, userID, transferReq), "failed to enqueue history update %v %v from transfer", walletID, userID),
			)
		}
		return errors.Wrapf(err, "failed to process transfer webhook with kind %s", kind)
	case webhookTransactionConfirmed, webhookTransactionBroadcasted:
		var transactionReq *webhookTransactionRequest = new(webhookTransactionRequest)
		if err := mapstructure.Decode(data["transactionRequest"], transactionReq); err != nil {
			return errors.Wrapf(err, "failed to decode transactionRequest payload from webhook %+v", data)
		}
		walletID := transactionReq.WalletID
		userID := transactionReq.Requester.UserID
		if missed {
			transactionReq = nil
		}
		return errors.Join(
			errors.Wrapf(a.enqueueAssetsUpdate(ctx, walletID, userID, transactionReq), "failed to enqueue assets update %v %v from transaction", walletID, userID),
			errors.Wrapf(a.enqueueHistoryUpdate(ctx, walletID, userID, transactionReq), "failed to enqueue history update %v %v from transaction", walletID, userID),
		)
	case webhookWalletBlockchainEvent:
		var blockchainEvent *webhookBlockchainEvent = new(webhookBlockchainEvent)
		if err := mapstructure.Decode(data["blockchainEvent"], blockchainEvent); err != nil {
			return errors.Wrapf(err, "failed to decode blockchainEvent payload from webhook %+v", data)
		}
		userID := ""
		w, hasWallet := data["wallet"]
		if hasWallet {
			var webhookWallet webhookBlockchainEventWallet
			if err := mapstructure.Decode(w, &webhookWallet); err != nil {
				return errors.Wrapf(err, "failed to decode wallet payload from webhook %+v", data)
			}
			userID = webhookWallet.SigningKey.DelegatedTo
			if _, err := a.getWallet(ctx, webhookWallet.ID); err != nil && storage.IsErr(err, storage.ErrNotFound) {
				if err = a.riverClient.Push(ctx, &webhookWalletInsertJobParams{
					UserID:   userID,
					WalletID: webhookWallet.ID,
					Wallet:   &webhookWallet,
				}); err != nil {
					return errors.Wrapf(err, "failed to enqueue wallet insert for wallet %v user %v", webhookWallet.ID, userID)
				}
			}
		}
		walletID := blockchainEvent.WalletID
		walletOwner, err := a.enqueuePublishKindFundSendNotify(ctx, walletID, blockchainEvent)
		if userID == "" {
			userID = walletOwner
		}

		if missed {
			blockchainEvent = nil // dedupl in river + sync in case there are more events (once per wallet, not per event)
		}
		return errors.Join(
			err,
			a.enqueueAssetsUpdate(ctx, walletID, userID, blockchainEvent),
			a.enqueueHistoryUpdate(ctx, walletID, userID, blockchainEvent),
		)
	default:
	}
	return nil
}

func (a *accounts) enqueuePublishKindFundSendNotify(ctx context.Context, walletID string, payload *webhookBlockchainEvent) (userID string, err error) {
	type userRelayAndWalletInfo struct {
		UserID           string                             `db:"user_id"`
		MasterPubkey     string                             `db:"master_pubkey"`
		IONConnectRelays relaymanagement.UserAssignedRelays `db:"ion_connect_relays"`
		External         bool                               `db:"external"`
	}

	relaysAndWallet, err := storage.Get[userRelayAndWalletInfo](ctx, a.db, `
	SELECT
		u.id as user_id,
		u.master_pubkey as master_pubkey,
		COALESCE((SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(u.ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x),'[]'::json) AS ion_connect_relays,
		sender IS NULL as external
		FROM wallets w 
		JOIN users u ON u.id = w.user_id
		LEFT JOIN wallets sender ON sender.address = $2
		WHERE w.id = $1
	`, walletID, payload.From)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return "", nil
		}
		return "", errors.Wrapf(err, "failed to get user relays for user wallet %v to publish 1756 event", walletID)
	}
	if !strings.EqualFold(payload.Direction, "In") {
		return relaysAndWallet.UserID, nil
	}
	if !relaysAndWallet.External {
		return relaysAndWallet.UserID, nil
	}

	writeRelayUrls := make([]string, 0, len(relaysAndWallet.IONConnectRelays))
	for _, r := range relaysAndWallet.IONConnectRelays {
		if r.Type == model.RelayListWriteMarker || r.Type == "" {
			writeRelayUrls = append(writeRelayUrls, r.URL)
		}
	}
	if len(writeRelayUrls) == 0 {
		if len(relaysAndWallet.IONConnectRelays) == 0 {
			return "", errors.New("no relays found for user")
		}
		writeRelayUrls = append(writeRelayUrls, relaysAndWallet.IONConnectRelays[0].URL)
	}

	if err = a.riverClient.Push(ctx, &webhookPublishKindFundSendNotifyJobParams{
		UserID:       relaysAndWallet.UserID,
		WalletID:     walletID,
		Payload:      payload,
		Relays:       writeRelayUrls,
		MasterPubkey: relaysAndWallet.MasterPubkey,
	}); err != nil {
		return "", errors.Wrapf(err, "failed to enqueue publishing 1756 for wallet %v user %v", walletID, relaysAndWallet.UserID)
	}
	return relaysAndWallet.UserID, nil
}
func (a *accounts) enqueueAssetsUpdate(ctx context.Context, walletID, userID string, payload any) error {
	if err := a.riverClient.Push(ctx, &webhookSyncAssetsJobParams{
		UserID:   userID,
		WalletID: walletID,
		Payload:  payload,
	}); err != nil {
		return errors.Wrapf(err, "failed to enqueue assets update for wallet %v user %v", walletID, userID)
	}
	return nil
}

func (a *accounts) enqueueTransferUpsert(ctx context.Context, walletID, userID string, payload *webhookTransferRequest) error {
	if err := a.riverClient.Push(ctx, &webhookTransferUpsertJobParams{
		UserID:   userID,
		WalletID: walletID,
		Payload:  payload,
	}); err != nil {
		return errors.Wrapf(err, "failed to enqueue transfer update for wallet %v user %v", walletID, userID)
	}
	return nil
}

func (a *accounts) enqueueHistoryUpdate(ctx context.Context, walletID, userID string, payload any) error {
	if err := a.riverClient.Push(ctx, &webhookSyncHistoryJobParams{
		UserID:   userID,
		WalletID: walletID,
		Payload:  payload,
	}); err != nil {
		return errors.Wrapf(err, "failed to enqueue history update for wallet %v user %v", walletID, userID)
	}
	return nil
}

func (webhookSyncAssetsJobParams) Kind() string {
	return "sync_assets"
}

func (w *webhookSyncAssetsWorker) Work(ctx context.Context, job *riverqueue.Job[webhookSyncAssetsJobParams]) error {
	args := job.Args
	assets, err := w.a.getWalletAssets(ctx, args.WalletID)
	if err != nil {
		return errors.Wrapf(err, "failed to get wallet assets for wallet %v user %v from 3rd party", args.WalletID, args.UserID)
	}

	return errors.Wrapf(w.a.upsertWalletAsset(ctx, args.UserID, args.WalletID, assets.Assets), "failed to upsert wallet assets for wallet %v user %v", args.WalletID, args.UserID)
}
func (a *accounts) upsertWalletAsset(ctx context.Context, userID, walletID string, assets []dfns.Asset) error {
	params, values, err := buildAssetsUpdate(walletID, userID, assets)
	if err != nil {
		return errors.Wrapf(err, "failed to read assets for wallet %v user %v", walletID, userID)
	}
	if len(params) == 0 {
		return nil
	}
	_, err = storage.Exec(ctx, a.db, `
		INSERT INTO wallet_assets (
			wallet_id,	user_id, balance, kind,	decimals, contract,
			symbol,	token_id, verified, raw
		) VALUES `+values+`
		ON CONFLICT (wallet_id, contract, token_id)
		DO UPDATE SET
		    updated_at = NOW(),
			user_id = EXCLUDED.user_id,
			balance = EXCLUDED.balance,
			kind = EXCLUDED.kind,
			decimals = EXCLUDED.decimals,
			symbol = EXCLUDED.symbol,
			verified = EXCLUDED.verified,
			raw = EXCLUDED.raw
	`, params...)
	if err != nil {
		return errors.Wrapf(err, "failed to upsert wallet asset wallet=%v", walletID)
	}
	log.Debug(fmt.Sprintf("Synced %+v assets for wallet %v user %v", assets, walletID, userID))
	return nil
}

func buildAssetsUpdate(walletID, userID string, assets []dfns.Asset) (params []any, val string, err error) {
	values := make([]string, 0, len(assets))
	i := 1
	for _, asset := range assets {
		kind, err := getString(asset, "kind")
		if err != nil {
			return nil, "", errors.Wrap(err, "failed to extract asset kind")
		}

		balance, err := getString(asset, "balance")
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to extract asset balance for kind %v", kind)
		}
		var decimals int64
		decimalsI, ok := asset["decimals"]
		if ok {
			if decF, isF := decimalsI.(float64); isF {
				decimals = int64(decF)
			}
			if decI, isI := decimalsI.(int); isI {
				decimals = int64(decI)
			}
		}

		symbol, _ := getString(asset, "symbol")
		tokenID, _ := getString(asset, "tokenId")
		contract, _ := getString(asset, "contract")

		if contract == "" && strings.EqualFold(kind, "tep74") {
			contract, _ = getString(asset, "master")
		}

		verified := false
		if verifiedVal, ok := asset["verified"]; ok && verifiedVal != nil {
			if v, okBool := verifiedVal.(bool); okBool {
				verified = v
			}
		}

		raw, err := json.Marshal(asset)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to marshal raw asset payload for wallet %v", walletID)
		}

		values = append(values, fmt.Sprintf("($%[1]v, $%[2]v, $%[3]v, $%[4]v, $%[5]v, $%[6]v, $%[7]v, $%[8]v, $%[9]v, $%[10]v)",
			i, i+1, i+2, i+3, i+4, i+5, i+6, i+7, i+8, i+9))
		params = append(params, walletID, userID, balance, kind, decimals, contract, symbol, tokenID, verified, string(raw))
		i += 10
	}
	return params, strings.Join(values, ", \n"), nil
}

func getString(asset dfns.Asset, key string) (string, error) {
	val, ok := asset[key]
	if !ok || val == nil {
		return "", nil
	}
	switch v := val.(type) {
	case string:
		return v, nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

func (webhookSyncHistoryJobParams) Kind() string {
	return "sync_history"
}

func (w *webhookSyncHistoryWorker) Work(ctx context.Context, job *riverqueue.Job[webhookSyncHistoryJobParams]) error {
	args := job.Args
	if args.Payload != nil {
		if webhookEvent, historyEventFromWebhook := args.Payload.(*webhookBlockchainEvent); historyEventFromWebhook {
			return errors.Wrapf(w.a.insertHistory(ctx, args.UserID, args.WalletID, []*webhookBlockchainEvent{webhookEvent}),
				"failed to insert history for user %v wallet %v", args.UserID, args.WalletID)
		}
		if webhookPayloadMap, ok := args.Payload.(map[string]any); ok {
			if _, ok = webhookPayloadMap["blockNumber"]; ok {
				var webhookEvent webhookBlockchainEvent
				if err := mapstructure.Decode(webhookPayloadMap, &webhookEvent); err != nil {
					return errors.Wrapf(err, "failed to decode webhook payload for user %v wallet %v", args.UserID, args.WalletID)
				}
				return errors.Wrapf(w.a.insertHistory(ctx, args.UserID, args.WalletID, []*webhookBlockchainEvent{&webhookEvent}),
					"failed to insert history for user %v wallet %v", args.UserID, args.WalletID)
			}
		}
	}
	// caused by transfer / etc, we need to fetch history first
	historyToStopFetching, err := storage.Get[history](ctx, w.a.db, `SELECT * FROM wallet_history WHERE wallet_id = $1 ORDER BY (block_number, i, log_index) DESC LIMIT 1`, args.WalletID)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			err = nil
		}
		if err != nil {
			return errors.Wrapf(err, "failed to get last synced history for user %v wallet %v", args.UserID, args.WalletID)
		}
	}
	newHistories := []*webhookBlockchainEvent{}
	var paginationToken *string = new("")
fetchingLoop:
	for ctx.Err() == nil && paginationToken != nil {
		histories, _, nextPagination, err := w.a.getWalletHistory(ctx, args.WalletID, *paginationToken, 100)
		if err != nil {
			return errors.Wrapf(err, "failed to fetch missed histories for %v %v after %T webhook: %+v", args.UserID, args.WalletID, args.Payload, args.Payload)
		}
		paginationToken = nextPagination
		for _, newHistoryMap := range histories {
			var newHistoryItem webhookBlockchainEvent
			if err = mapstructure.Decode(newHistoryMap, &newHistoryItem); err != nil {
				return errors.Wrapf(err, "failed to decode history item for %v %v in webhook fetch", args.UserID, args.WalletID)
			}
			if historyToStopFetching != nil && newHistoryItem.TxHash == historyToStopFetching.TxHash && newHistoryItem.Index == fmt.Sprintf("%v", historyToStopFetching.LogIndex) {
				break fetchingLoop
			}
			newHistories = append(newHistories, &newHistoryItem)
		}
	}
	if err = w.a.insertHistory(ctx, args.UserID, args.WalletID, newHistories); err != nil {
		return errors.Wrapf(err, "failed to insert %v new histories for %v %v after %T webhook: %+v", len(newHistories), args.UserID, args.WalletID, args.Payload, args.Payload)
	}

	return nil
}

func (a *accounts) insertHistory(ctx context.Context, userID, walletID string, args []*webhookBlockchainEvent) error {
	txs, values, params := buildHistoryParams(userID, args)
	if len(txs) == 0 {
		return nil
	}
	_, err := storage.Exec(ctx, a.db, `
		INSERT INTO wallet_history (user_id, wallet_id, tx_hash, external_hash, log_index, block_number, timestamp, network, kind, direction, contract, symbol, decimals, value, fee, from_address, to_address, org_id, metadata, memo, token_id) 
		VALUES `+values+` ON CONFLICT (wallet_id, tx_hash, log_index) DO NOTHING;`,
		params...,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to insert history item for user %v wallet %v", userID, walletID)
	}

	log.Debug(fmt.Sprintf("Synced %v history items for user %v wallet %v: %+v", len(args), userID, walletID, txs))

	return nil
}

func buildHistoryParams(userID string, args []*webhookBlockchainEvent) ([]string, string, []any) {
	var params []any
	var values, txs []string
	i := 1
	for _, arg := range args {
		values = append(values, fmt.Sprintf(
			"($%[1]v, $%[2]v, $%[3]v, $%[4]v, $%[5]v, $%[6]v, $%[7]v, $%[8]v, $%[9]v, $%[10]v, $%[11]v, $%[12]v, $%[13]v, $%[14]v, $%[15]v, $%[16]v, $%[17]v, $%[18]v, $%[19]v, $%[20]v, $%[21]v)",
			i, i+1, i+2, i+3, i+4, i+5, i+6, i+7, i+8, i+9, i+10, i+11, i+12, i+13, i+14, i+15, i+16, i+17, i+18, i+19, i+20,
		))
		params = append(params, userID, arg.WalletID, arg.TxHash, arg.ExternalHash, arg.Index, arg.BlockNumber, arg.Timestamp, arg.Network, arg.Kind, arg.Direction, arg.Contract, arg.Symbol, arg.Decimals, arg.Value, arg.Fee, arg.From, arg.To, arg.OrgID, arg.Metadata, arg.Memo, arg.TokenId)
		txs = append(txs, arg.TxHash)
		i += 21
	}
	return txs, strings.Join(values, ", \n"), params
}

func (webhookTransferUpsertJobParams) Kind() string {
	return "upsert_transfer"
}

func (w *webhookTransferUpsertWorker) Work(ctx context.Context, job *riverqueue.Job[webhookTransferUpsertJobParams]) error {
	args := job.Args
	return errors.Wrapf(w.upsertTransfer(ctx, args.UserID, args.WalletID, args.Payload),
		"failed to insert history for user %v wallet %v", args.UserID, args.WalletID)
}
func (w *webhookTransferUpsertWorker) upsertTransfer(ctx context.Context, userID, walletID string, payload *webhookTransferRequest) error {
	kind := payload.RequestBody.Kind
	contract := payload.RequestBody.Contract
	tokenID := payload.TokenID

	switch {
	case strings.EqualFold(kind, "tep74"):
		if contract == "" {
			contract = payload.Master
		}
	case strings.EqualFold(kind, "spl"):
		if contract == "" {
			contract = payload.Mint
		}
	case strings.EqualFold(kind, "spl2022"):
		if contract == "" {
			contract = payload.Mint
		}
	case strings.EqualFold(kind, "sep41"):
		if contract == "" {
			contract = payload.Issuer
		}
		if tokenID == "" {
			tokenID = payload.AssetCode
		}
	case strings.EqualFold(kind, "asa"):
		if tokenID == "" {
			tokenID = payload.AssetID
		}
	}

	if payload.DateRequested == "" {
		return errors.Errorf("dateRequested is empty")
	}
	requestedParsed, err := stdlibtime.Parse(stdlibtime.RFC3339, payload.DateRequested)
	if err != nil {
		return errors.Wrapf(err, "invalid dateRequested %q", payload.DateRequested)
	}
	requestedAt := time.New(requestedParsed)

	var broadcastedAt *time.Time
	if payload.DateBroadcasted != "" {
		broadcastedParsed, parseErr := stdlibtime.Parse(stdlibtime.RFC3339, payload.DateBroadcasted)
		if parseErr != nil {
			return errors.Wrapf(parseErr, "invalid dateBroadcasted %q", payload.DateBroadcasted)
		}
		broadcastedAt = time.New(broadcastedParsed)
	}

	var confirmedAt *time.Time
	if payload.DateConfirmed != "" {
		confirmedParsed, parseErr := stdlibtime.Parse(stdlibtime.RFC3339, payload.DateConfirmed)
		if parseErr != nil {
			return errors.Wrapf(parseErr, "invalid dateConfirmed %q", payload.DateConfirmed)
		}
		confirmedAt = time.New(confirmedParsed)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal transfer payload for wallet %v", walletID)
	}

	_, err = storage.Exec(ctx, w.a.db, `
		INSERT INTO wallet_transfers (
			user_id, wallet_id,	id,	network, kind,	status,	contract, token_id,	amount,	fee,
			from_address, to_address,	tx_hash, requester_user_id,	date_requested,	date_broadcasted, date_confirmed, raw
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18
		)
		ON CONFLICT (id)
		DO UPDATE SET
		    updated_at = NOW(),
			user_id = EXCLUDED.user_id,
			network = EXCLUDED.network,
			kind = EXCLUDED.kind,
			status = EXCLUDED.status,
			contract = EXCLUDED.contract,
			token_id = EXCLUDED.token_id,
			amount = EXCLUDED.amount,
			fee = EXCLUDED.fee,
			from_address = EXCLUDED.from_address,
			to_address = EXCLUDED.to_address,
			tx_hash = EXCLUDED.tx_hash,
			requester_user_id = EXCLUDED.requester_user_id,
			date_requested = EXCLUDED.date_requested,
			date_broadcasted = EXCLUDED.date_broadcasted,
			date_confirmed = EXCLUDED.date_confirmed,
			raw = EXCLUDED.raw
	`,
		userID, walletID, payload.ID, payload.Network, kind, payload.Status, contract, tokenID,
		payload.RequestBody.Amount, payload.Fee, walletID, payload.RequestBody.To,
		payload.TxHash, payload.Requester.UserID, requestedAt, broadcastedAt, confirmedAt, raw,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to upsert transfer id=%v wallet=%v", payload.ID, walletID)
	}
	log.Debug(fmt.Sprintf("Synced transfer %v %v for user %v wallet %v", payload.ID, payload.TxHash, userID, walletID))
	return nil
}

func (webhookWalletInsertJobParams) Kind() string {
	return "insert_wallet"
}

func (w *webhookWalletInsertWorker) Work(ctx context.Context, job *riverqueue.Job[webhookWalletInsertJobParams]) error {
	args := job.Args
	return errors.Wrapf(w.a.storeUserWallet(ctx, args.UserID, webhookToWallet(args.Wallet)),
		"failed to store wallet %v for user %v", args.WalletID, args.UserID)
}

func (a *accounts) processMissedWebhookEvents(ctx context.Context, missedWebhookEvents <-chan map[string]interface{}) {
	for missedWHEvent := range missedWebhookEvents {
		kind := missedWHEvent["whKind"].(string)
		delete(missedWHEvent, "whKind")
		ctxProcessing, cancel := context.WithTimeout(ctx, 30*stdlibtime.Second)
		if err := a.processWebhookFromDelegatedRelyingParty(ctxProcessing, kind, missedWHEvent, true); err != nil {
			log.Error(errors.Wrapf(err, "failed to process missed webhook %v %+v", kind, missedWHEvent))
		}
		cancel()
	}
}

func (webhookPublishKindFundSendNotifyJobParams) Kind() string {
	return "publish_1756"
}

func (w *webhookPublishKindFundSendNotifyWorker) Work(ctx context.Context, job *riverqueue.Job[webhookPublishKindFundSendNotifyJobParams]) (err error) {
	args := job.Args
	var coin *coins.Coin
	if args.Payload.Kind == "NativeTransfer" {
		coin, err = w.a.coinsRepo.GetNativeCoinForNetwork(ctx, args.Payload.Network)
		if err != nil {
			return errors.Wrapf(err, "failed to get native coin for network %v to populate amount_usd", args.Payload.Network)
		}
	} else if args.Payload.Contract != "" {
		symbol := args.Payload.Symbol
		if symbol == "" {
			symbol = args.Payload.Metadata.Asset.Symbol
		}
		var matchingCoins []*coins.Coin
		matchingCoins, err = w.a.coinsRepo.GetCoinForContractAddressOrSymbol(ctx, args.Payload.Network, args.Payload.Contract, symbol)
		if err != nil {
			return errors.Wrapf(err, "failed to get coin for contract %v symbol %v to populate amount_usd", args.Payload.Contract, symbol)
		}
		if len(matchingCoins) > 0 {
			coin = matchingCoins[0] // known coin to calc amountUSD
		}
	}

	event, err := w.generateKindFundSendNotifyEvent(args.MasterPubkey, args.Payload, coin)
	if err != nil {
		return errors.Wrapf(err, "failed to generate kind 1756 event for user %v wallet %v", args.UserID, args.WalletID)
	}
	if err = publishEvents(ctx, args.Relays, []*model.Event{event}, w.a.privateKey); err != nil {
		return errors.Wrapf(err, "failed to publish kind 1756 event for user %v wallet %v", args.UserID, args.WalletID)
	}
	return nil
}
func (w *webhookPublishKindFundSendNotifyWorker) generateKindFundSendNotifyEvent(masterKey string, whEvent *webhookBlockchainEvent, coin *coins.Coin) (*model.Event, error) {
	now := nostr.Now()
	type fundSendContent struct {
		Amount    string `json:"amount"`
		AmountUSD string `json:"amount_usd"`
		AssetID   string `json:"asset_id,omitempty"`
		TxHash    string `json:"tx_hash"`
		TxURL     string `json:"tx_url"`
		From      string `json:"from"`
		To        string `json:"to"`
	}
	var network *coins.Network
	for _, n := range w.a.coinsRepo.GetAllNetworks() {
		if n.ID == whEvent.Network {
			network = n
			break
		}
	}
	if network == nil {
		return nil, errors.Errorf("webhook event for unknown network %v", whEvent.Network)
	}
	usdAmount := "0"
	if coin != nil {
		valueF, ok := new(big.Float).SetString(whEvent.Value)
		if !ok {
			return nil, errors.Errorf("malformed value in tx %v: %v", whEvent.TxHash, whEvent.Value)
		}
		valueInTokens, _ := valueF.Quo(valueF, big.NewFloat(math.Pow(10, float64(coin.Decimals)))).Float64()
		usdAmount = fmt.Sprintf("%.18f", valueInTokens*coin.PriceUSD)
	}
	contentData := &fundSendContent{
		Amount:    whEvent.Value,
		AmountUSD: usdAmount,
		TxHash:    whEvent.TxHash,
		TxURL:     strings.ReplaceAll(network.ExplorerURL, "{txHash}", whEvent.TxHash),
		From:      whEvent.From,
		To:        whEvent.To,
	}

	if whEvent.TokenId != "" {
		contentData.AssetID = whEvent.TokenId
	}
	content, err := json.Marshal(contentData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal content for 1756 wallet %v network %v", whEvent.WalletID, whEvent.Network)
	}
	assetAddress := whEvent.Contract
	if assetAddress == "" {
		assetAddress = whEvent.Symbol
	}
	if assetAddress == "" {
		assetAddress = whEvent.Metadata.Asset.Symbol
	}
	event := &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      model.CustomIONKindFundSendNotify,
			Content:   string(content),
			Tags: nostr.Tags{
				{"network", network.ID},
				{"asset_class", whEvent.Kind},
				{"asset_address", assetAddress},
				{"p", masterKey},
			},
		},
	}
	if err = event.SignWithAlg(w.a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		log.Panic(errors.Wrap(err, "failed to sign 1756 fund send notify event"))
	}

	return event, nil
}
