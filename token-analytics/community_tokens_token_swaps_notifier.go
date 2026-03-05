// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

const tokenSwapUpdatesChannel = "token_swap_updates"

type tokenSwapUpdate struct {
	TransactionHash       string  `json:"transaction_hash"`
	ContractAddress       string  `json:"contract_address"`
	ExternalAddress       string  `json:"external_address"`
	UserBlockchainAddress string  `json:"user_blockchain_address"`
	Direction             bool    `json:"direction"`
	InputAmount           string  `json:"input_amount"`
	OutputAmount          string  `json:"output_amount"`
	CurvePriceUSD         float64 `json:"curve_price_usd"`
	CreatedAt             int64   `json:"created_at"`
	BaseToken             string  `json:"base_token"`
	TotalSupply           string  `json:"total_supply"`
	PairId                string  `json:"pair_id"`
	Burned                string  `json:"burned"`
	Platform              string  `json:"platform"`
	Type                  string  `json:"type"`
}

func (t *tokenAnalytics) startTokenSwapNotifier(ctx context.Context) {
	log.Info(fmt.Sprintf("Token swap notifier starting, subscribing to %s notifications", tokenSwapUpdatesChannel))

	go func() {
		if err := t.listenTokenSwapUpdates(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				log.Info("Token swap notifier stopped due to context cancellation")
				return
			}
			log.Error(errors.Wrap(err, "token swap notifier initial start failed, starting retry loop"))

			retryWithBackoff(ctx, "Token swap notifier", t.listenTokenSwapUpdates)
		}
	}()
}

func (t *tokenAnalytics) listenTokenSwapUpdates(ctx context.Context) error {
	listener, err := t.ingestedDataDB.Listen(ctx, tokenSwapUpdatesChannel)
	if err != nil {
		return errors.Wrapf(err, "failed to create listener for %s", tokenSwapUpdatesChannel)
	}
	defer listener.Close()

	myPID := listener.BackendPID()
	log.Info(fmt.Sprintf("Successfully subscribed to %s pg channel (backend PID: %d)", tokenSwapUpdatesChannel, myPID))
	ch := listener.Channel()

	for {
		select {
		case <-ctx.Done():
			log.Info("Token swap notifier stopped due to context cancellation")
			return nil

		case notification, ok := <-ch:
			if !ok {
				if err := listener.Err(); err != nil {
					return errors.Wrapf(err, "listener pg channel closed due to error")
				}
				return errors.New("listener pg channel closed normally")
			}
			if notification.PID == myPID {
				log.Debug(fmt.Sprintf("Ignoring self-notification from backend PID %d for token swap update", myPID))
				continue
			}

			if err := t.handleTokenSwapUpdate(ctx, notification.Payload); err != nil {
				log.Error(errors.Wrap(err, "failed to handle token swap update"))
			}
		}
	}
}

func (t *tokenAnalytics) handleTokenSwapUpdate(ctx context.Context, payload string) error {
	var update tokenSwapUpdate
	if err := json.Unmarshal([]byte(payload), &update); err != nil {
		return errors.Wrap(err, "failed to unmarshal token swap update")
	}

	log.Debug("Received token swap update",
		"tx", update.TransactionHash,
		"contract", update.ContractAddress,
		"user", update.UserBlockchainAddress,
		"price_usd", update.CurvePriceUSD)

	inputAmount := new(big.Int)
	if _, ok := inputAmount.SetString(update.InputAmount, 10); !ok {
		return errors.Errorf("failed to parse input_amount: %s", update.InputAmount)
	}
	outputAmount := new(big.Int)
	if _, ok := outputAmount.SetString(update.OutputAmount, 10); !ok {
		return errors.Errorf("failed to parse output_amount: %s", update.OutputAmount)
	}
	totalSupply := new(big.Int)
	if _, ok := totalSupply.SetString(update.TotalSupply, 10); !ok {
		return errors.Errorf("failed to parse total_supply: %s", update.TotalSupply)
	}
	burned := new(big.Int)
	if _, ok := burned.SetString(update.Burned, 10); !ok {
		return errors.Errorf("failed to parse burned: %s", update.Burned)
	}
	pairIdBytes, err := hex.DecodeString(strings.TrimPrefix(update.PairId, "0x"))
	if err != nil {
		return errors.Wrapf(err, "failed to decode pair_id: %s", update.PairId)
	}
	mCapUSDF := marketCap(update.CurvePriceUSD, totalSupply, burned)
	mCapUSD, _ := mCapUSDF.Float64()

	tx := &txEvent{
		TransactionHash: update.TransactionHash,
		BlockTimestamp:  time.New(stdlibtime.UnixMicro(update.CreatedAt)),
	}
	registered, regErr := t.registerTrade(ctx, tx, update.Direction, inputAmount, outputAmount,
		update.ContractAddress, update.UserBlockchainAddress, update.ExternalAddress,
		update.BaseToken, pairIdBytes, totalSupply, burned, update.CurvePriceUSD, mCapUSD)
	if regErr != nil {
		return errors.Wrapf(regErr, "failed to register trade for tx %s", update.TransactionHash)
	}
	if !registered {
		log.Debug(fmt.Sprintf("[PG_NOTIFY] skipping duplicate trade for tx=%s, contract=%s", update.TransactionHash, update.ContractAddress))

		return nil
	}
	if err = t.updateTokenRankingsInRedis(ctx, mCapUSD, update.ExternalAddress, update.Platform, update.Type); err != nil {
		return errors.Wrapf(err, "failed to update redis ranking for tx %v contract %v %v user %v to notify subscribers",
			update.TransactionHash, update.ContractAddress, update.ExternalAddress, update.UserBlockchainAddress)
	}
	tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, update.TransactionHash, update.ContractAddress, update.UserBlockchainAddress)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v contract %v user %v to notify subscribers",
			update.TransactionHash, update.ContractAddress, update.UserBlockchainAddress))
		return nil
	}

	log.Debug(fmt.Sprintf("[PG_NOTIFY->NOTIFY_SWAP] tx=%s, external_address=%s, direction=%v, input=%s, output=%s, price_usd=%.6f, mcap_usd=%.2f",
		update.TransactionHash, tradeInfo.TokenExternalAddress, update.Direction, update.InputAmount, update.OutputAmount, update.CurvePriceUSD, mCapUSD))

	t.subscriptions.NotifySwap(tradeInfo)

	return nil
}

func (t *tokenAnalytics) updateTokenRankingsInRedis(ctx context.Context, mCapUSD float64, externalAddress, platform, tokenType string) error {
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if pErr := pipeliner.ZAdd(ctx, globalTopSetKey, redis.Z{
			Score:  mCapUSD,
			Member: externalAddress,
		}).Err(); pErr != nil {
			return pErr
		}
		if platform == PlatformGroupXCom {
			if pErr := pipeliner.ZAdd(ctx, globalTopXcomSetKey, redis.Z{
				Score:  mCapUSD,
				Member: externalAddress,
			}).Err(); pErr != nil {
				return pErr
			}
		}
		if tokenType != "" {
			if typeSpecificKey := getTopSetKeyByType(tokenType); typeSpecificKey != "" {
				if pErr := pipeliner.ZAdd(ctx, typeSpecificKey, redis.Z{
					Score:  mCapUSD,
					Member: externalAddress,
				}).Err(); pErr != nil {
					return pErr
				}
			}
			if IsContentType(tokenType) {
				if pErr := pipeliner.ZAdd(ctx, globalTopAnyPostSetKey, redis.Z{
					Score:  mCapUSD,
					Member: externalAddress,
				}).Err(); pErr != nil {
					return pErr
				}
			}
		}
		if platform == PlatformGroupXCom || tokenType == TokenTypeProfile {
			if pErr := pipeliner.ZAdd(ctx, globalTopXcomCombinedSetKey, redis.Z{
				Score:  mCapUSD,
				Member: externalAddress,
			}).Err(); pErr != nil {
				return pErr
			}
		}
		return nil
	}); txErr != nil {
		return txErr
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil {
				return fmt.Errorf("failed to `%v`  for token %v: %w", response.FullName(), externalAddress, rerr)
			}
		}
	}
	return nil
}
