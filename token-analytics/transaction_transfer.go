// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

type tokenInfo struct {
	ExternalAddress string `db:"external_address"`
	PairID          string `db:"pair_id"`
	BaseToken       string `db:"base_token"`
	Type            string `db:"type"`
	Platform        string `db:"platform"`
	Burned          string `db:"burned"`
	Ticker          string `db:"ticker"`
}

func (t *tokenAnalytics) onTransfer(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTransfer) error {
	log.Debug(fmt.Sprintf("onTransfer: token=%s from=%s to=%s amount=%s tx=%s",
		ev.TokenAddress.Hex(), ev.From.Hex(), ev.To.Hex(), ev.Value.String(), tx.TransactionHash))

	if t.isSwapTransaction(tx) {
		log.Debug(fmt.Sprintf("Skipping Transfer event in swap transaction %s", tx.TransactionHash))

		return nil
	}

	zeroAddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	burnAddr := common.HexToAddress(t.cfg.BondingCurve.BurnAddress)
	if ev.From == zeroAddr || ev.From == burnAddr {
		log.Debug(fmt.Sprintf("Skipping burn transfer in tx %s (from=%s, to=%s)",
			tx.TransactionHash, ev.From.Hex(), ev.To.Hex()))
		return nil
	}
	tokenData, err := t.getTokenInfo(ctx, ev.TokenAddress.Hex())
	if err != nil {
		log.Debug(fmt.Sprintf("Token %s not found in DB, skipping transfer", ev.TokenAddress.Hex()))

		return nil
	}
	log.Debug(fmt.Sprintf("Processing P2P transfer: token=%s from=%s to=%s amount=%s tx=%s",
		ev.TokenAddress.Hex(), ev.From.Hex(), ev.To.Hex(), ev.Value.String(), tx.TransactionHash))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return t.enqueueBalanceUpdate(gctx, tx, ev.From.Hex(), ev.TokenAddress.Hex(), tokenData, ev.Value, false)
	})
	txToBurn := ev.To == zeroAddr || ev.To == burnAddr
	if !txToBurn {
		g.Go(func() error {
			return t.enqueueBalanceUpdate(gctx, tx, ev.To.Hex(), ev.TokenAddress.Hex(), tokenData, ev.Value, true)
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrapf(err, "failed to enqueue balance updates for transfer tx %s", tx.TransactionHash)
	}
	log.Debug(fmt.Sprintf("Successfully enqueued balance updates for transfer: token=%s from=%s to=%s tx=%s",
		ev.TokenAddress.Hex(), ev.From.Hex(), ev.To.Hex(), tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) isSwapTransaction(tx *txEvent) bool {
	for _, logEvent := range tx.Logs {
		topic0, _ := logEvent.getString("topic0")
		if topic0 == bondingcurve.EventSwappedSignature || topic0 == bondingcurve.EventUniswapSwappedSignature {
			return true
		}
	}

	return false
}

func (t *tokenAnalytics) getTokenInfo(ctx context.Context, contractAddress string) (*tokenInfo, error) {
	query := `
		SELECT
			external_address,
			COALESCE(pair_id, '') AS pair_id,
			COALESCE(base_token, '') AS base_token,
			COALESCE(type, '') AS type,
			platform,
			COALESCE(burned.amount, '0') as burned,
			t.ticker
		FROM tokens 
		LEFT JOIN fees_transferred burned ON burned.token_external_address = tokens.external_address AND burned.recipient_bsc_address = $2
		WHERE contract_address = $1
		LIMIT 1
	`
	row, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, query, strings.ToLower(contractAddress), t.cfg.BondingCurve.BurnAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get token info for contract %s", contractAddress)
	}

	return row, nil
}

func (t *tokenAnalytics) getUserExternalAddress(ctx context.Context, blockchainAddress string) (string, error) {
	type userExternalAddressRow struct {
		ExternalAddress string `db:"external_address"`
	}
	query := `
		SELECT u.external_address
		FROM user_bsc_addresses uba
		JOIN users u ON u.id = uba.user_id
		WHERE uba.bsc_address = $1
		LIMIT 1
	`
	row, err := storage.Get[userExternalAddressRow](ctx, t.ingestedDataDB, query, strings.ToLower(blockchainAddress))
	if err != nil {
		return "", errors.Wrapf(err, "failed to get user external address for blockchain address %s", blockchainAddress)
	}

	return row.ExternalAddress, nil
}

func (t *tokenAnalytics) enqueueBalanceUpdate(ctx context.Context, tx *txEvent, userBlockchainAddress, tokenContractAddress string, tokenData *tokenInfo, transferAmount *big.Int, isAddition bool) error {
	userExternalAddress, err := t.getUserExternalAddress(ctx, userBlockchainAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get user external address for %s", userBlockchainAddress)
	}
	burnedBig := new(big.Int)
	burnedBig.SetString(tokenData.Burned, 10)
	jobArgs := BalanceUpdateJobArgs{
		UserBlockchainAddress: strings.ToLower(userBlockchainAddress),
		UserExternalAddress:   userExternalAddress,
		ContractAddress:       strings.ToLower(tokenContractAddress),
		TokenExternalAddress:  tokenData.ExternalAddress,
		TransactionHash:       tx.TransactionHash,
		BlockNumber:           tx.BlockNumber,
		PairID:                tokenData.PairID,
		BaseToken:             tokenData.BaseToken,
		TokenType:             tokenData.Type,
		Platform:              tokenData.Platform,
		Burned:                burnedBig,
		Ticker:                tokenData.Ticker,
	}
	if t.cfg.EnableDummyGenerator {
		userPositionKey := keyUserPositionOfToken(tokenData.ExternalAddress)
		currentScore, err := t.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddress).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			log.Error(errors.Wrapf(err, "failed to get current user position for dummy transfer"))

			currentScore = 0
		}

		amountFloat := weiToFloat64FromBigInt(transferAmount)
		var newScore float64
		if isAddition {
			// Receiver: add amount
			newScore = currentScore + amountFloat
		} else {
			// Sender: subtract amount
			newScore = math.Max(0, currentScore-amountFloat)
		}

		newBalanceWei := new(big.Float).Mul(big.NewFloat(newScore), big.NewFloat(1e18))
		newBalanceBigInt, accuracy := newBalanceWei.Int(nil)
		if accuracy != big.Exact {
			log.Warn(fmt.Sprintf("Dummy transfer: Float to Int conversion lost precision (accuracy=%v) for user=%s, token=%s",
				accuracy, userBlockchainAddress, tokenData.ExternalAddress))
		}
		if newBalanceBigInt.Sign() < 0 {
			log.Debug(fmt.Sprintf("Dummy transfer: NEGATIVE DETECTED! Setting to 0. Was: %s, newScore=%.2f, user=%s",
				newBalanceBigInt.String(), newScore, userBlockchainAddress))
			newBalanceBigInt = big.NewInt(0)
		}
		balanceStr := newBalanceBigInt.String()
		jobArgs.DummyBalance = &balanceStr

		operation := "subtract"
		if isAddition {
			operation = "add"
		}
		log.Debug(fmt.Sprintf("Dummy transfer: Calculated balance=%s (current=%.2f, %s=%.2f, new=%.2f) for user=%s, token=%s",
			balanceStr, currentScore, operation, amountFloat, newScore, userBlockchainAddress, tokenData.ExternalAddress))
	}
	if err := t.riverClient.Push(ctx, jobArgs); err != nil {
		return errors.Wrapf(err, "failed to enqueue balance update job for tx %v", tx.TransactionHash)
	}

	log.Debug(fmt.Sprintf("Enqueued balance update: user=%s token=%s tx=%s",
		userBlockchainAddress, tokenContractAddress, tx.TransactionHash))

	return nil
}
