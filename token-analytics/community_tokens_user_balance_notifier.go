// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/log"
)

type (
	userBalanceUpdate struct {
		UserBlockchainAddress string `json:"user_blockchain_address"`
		UserExternalAddress   string `json:"user_external_address"`
		ContractAddress       string `json:"contract_address"`
		ExternalAddress       string `json:"external_address"`
		Amount                string `json:"amount"`
		UpdatedAt             int64  `json:"updated_at"`
	}
)

func (t *tokenAnalytics) startUserBalanceNotifier(ctx context.Context) {
	log.Info(fmt.Sprintf("User balance notifier starting, subscribing to %s notifications", userBalanceUpdatesChannel))

	go func() {
		if err := t.listenUserBalanceUpdates(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				log.Info("User balance notifier stopped due to context cancellation")
				return
			}
			log.Error(errors.Wrap(err, "user balance notifier initial start failed, starting retry loop"))

			retryWithBackoff(ctx, "User balance notifier", t.listenUserBalanceUpdates)
		}
	}()
}

func (t *tokenAnalytics) listenUserBalanceUpdates(ctx context.Context) error {
	listener, err := t.ingestedDataDB.Listen(ctx, userBalanceUpdatesChannel)
	if err != nil {
		return errors.Wrapf(err, "failed to create listener for %s", userBalanceUpdatesChannel)
	}
	defer listener.Close()

	myPID := listener.BackendPID()
	log.Info(fmt.Sprintf("Successfully subscribed to %s pg channel (backend PID: %d)", userBalanceUpdatesChannel, myPID))
	ch := listener.Channel()

	for {
		select {
		case <-ctx.Done():
			log.Info("User balance notifier stopped due to context cancellation")
			return nil

		case notification, ok := <-ch:
			if !ok {
				if err := listener.Err(); err != nil {
					return errors.Wrapf(err, "listener pg channel closed due to error")
				}
				return errors.New("listener pg channel closed normally")
			}
			if notification.PID == myPID {
				log.Debug(fmt.Sprintf("Ignoring self-notification from backend PID %d for user balance update", myPID))

				continue
			}
			if err := t.handleUserBalanceUpdate(ctx, notification.Payload); err != nil {
				log.Error(errors.Wrapf(err, "failed to handle user balance update notification: %s", notification.Payload))
			}
		}
	}
}

func (t *tokenAnalytics) handleUserBalanceUpdate(ctx context.Context, payload string) error {
	var update userBalanceUpdate
	if err := json.Unmarshal([]byte(payload), &update); err != nil {
		return errors.Wrapf(err, "failed to unmarshal user balance update payload: %s", payload)
	}

	log.Debug(fmt.Sprintf("Received user balance update notification: user=%s, token=%s, amount=%s",
		update.UserExternalAddress, update.ExternalAddress, update.Amount))

	balanceBig := new(big.Int)
	if _, ok := balanceBig.SetString(update.Amount, 10); !ok {
		return fmt.Errorf("failed to parse amount: %s", update.Amount)
	}
	balanceFloat := weiToFloat64FromBigInt(balanceBig)

	userPositionKey := keyUserPositionOfToken(update.ExternalAddress)
	userPositionKeyByBlockchainAddress := keyUserPositionOfTokenByUserBlockchainAddress(update.ExternalAddress)

	if balanceFloat <= 0 {
		if err := t.processedDataDB.ZRem(ctx, userPositionKey, update.UserExternalAddress).Err(); err != nil {
			return errors.Wrapf(err, "failed to remove user position from Redis for user %s token %s",
				update.UserExternalAddress, update.ExternalAddress)
		}
		if err := t.processedDataDB.ZRem(ctx, userPositionKeyByBlockchainAddress, update.UserBlockchainAddress).Err(); err != nil {
			return errors.Wrapf(err, "failed to remove user position from Redis for user %s token %s",
				update.UserBlockchainAddress, update.ExternalAddress)
		}
		log.Debug(fmt.Sprintf("Removed user position from Redis: user=%s, token=%s",
			update.UserExternalAddress, update.ExternalAddress))
	} else {
		if err := t.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{
			Score:  balanceFloat,
			Member: update.UserExternalAddress,
		}).Err(); err != nil {
			return errors.Wrapf(err, "failed to add user position to Redis for user %s token %s",
				update.UserExternalAddress, update.ExternalAddress)
		}
		if err := t.processedDataDB.ZAdd(ctx, userPositionKeyByBlockchainAddress, redis.Z{
			Score:  balanceFloat,
			Member: update.UserBlockchainAddress,
		}).Err(); err != nil {
			return errors.Wrapf(err, "failed to add user position to Redis for user %s token %s",
				update.UserBlockchainAddress, update.ExternalAddress)
		}
		log.Debug(fmt.Sprintf("Updated user position in Redis: user=%s, token=%s, balance=%.2f",
			update.UserExternalAddress, update.ExternalAddress, balanceFloat))
	}

	return nil
}
