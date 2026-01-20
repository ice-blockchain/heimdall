// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type BalanceUpdateJobArgs struct {
	UserBlockchainAddress string `json:"user_blockchain_address"`
	UserExternalAddress   string `json:"user_external_address"`
	ContractAddress       string `json:"contract_address"`
	TokenExternalAddress  string `json:"token_external_address"`
	TransactionHash       string `json:"transaction_hash"`

	DummyBalance *string `json:"dummy_balance,omitempty"`
}

func (BalanceUpdateJobArgs) Kind() string {
	return "balance_update"
}

type balanceUpdateWorker struct {
	bondingCurve    bondingcurve.BondingCurve
	ingestedDataDB  *storage.DB
	processedDataDB storagev3.DB
	riverqueue.WorkerDefaults[BalanceUpdateJobArgs]
}

func (w *balanceUpdateWorker) Work(ctx context.Context, job *riverqueue.Job[BalanceUpdateJobArgs]) error {
	args := job.Args

	log.Debug(fmt.Sprintf("Processing balance update job: user=%s, token=%s, tx=%s, dummy=%v",
		args.UserBlockchainAddress, args.TokenExternalAddress, args.TransactionHash, args.DummyBalance != nil))

	var balance *big.Int
	var err error

	if args.DummyBalance != nil {
		balance = new(big.Int)
		if _, ok := balance.SetString(*args.DummyBalance, 10); !ok {
			return errors.Errorf("invalid dummy balance format: %s", *args.DummyBalance)
		}
		log.Debug(fmt.Sprintf("Using dummy balance: %s for user=%s, token=%s",
			*args.DummyBalance, args.UserBlockchainAddress, args.TokenExternalAddress))
	} else {
		tokenAddr := common.HexToAddress(args.ContractAddress)
		userAddr := common.HexToAddress(args.UserBlockchainAddress)

		balance, err = w.bondingCurve.GetTokenBalance(ctx, tokenAddr, userAddr)
		if err != nil {
			return errors.Wrapf(err, "failed to get token balance for user %s token %s",
				args.UserBlockchainAddress, args.ContractAddress)
		}
	}

	_, err = storage.Exec(ctx, w.ingestedDataDB, `
		INSERT INTO user_token_positions (
			user_blockchain_address, contract_address, external_address, user_external_address,
			amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, updated_at
		)
		VALUES (
			$1, $2, $3, $4,
			$5, 0, 0, 0, NOW()
		)
		ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
			amount = EXCLUDED.amount,
			updated_at = EXCLUDED.updated_at;
	`, args.UserBlockchainAddress, args.ContractAddress, args.TokenExternalAddress,
		args.UserExternalAddress, balance.String())
	if err != nil {
		return errors.Wrapf(err, "failed to update user token position in DB for user %s token %s",
			args.UserBlockchainAddress, args.ContractAddress)
	}

	userPositionKey := keyUserPositionOfToken(args.TokenExternalAddress)
	balanceFloat := weiToFloat64FromBigInt(balance)

	if balanceFloat <= 0 {
		if err := w.processedDataDB.ZRem(ctx, userPositionKey, args.UserExternalAddress).Err(); err != nil {
			return errors.Wrapf(err, "failed to remove user position from Redis for user %s token %s",
				args.UserExternalAddress, args.TokenExternalAddress)
		}
	} else {
		if err := w.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{
			Score:  balanceFloat,
			Member: args.UserExternalAddress,
		}).Err(); err != nil {
			return errors.Wrapf(err, "failed to add user position to Redis for user %s token %s",
				args.UserExternalAddress, args.TokenExternalAddress)
		}
	}

	log.Debug(fmt.Sprintf("Balance updated: user=%s, token=%s, balance=%s",
		args.UserBlockchainAddress, args.TokenExternalAddress, balance.String()))

	return nil
}
