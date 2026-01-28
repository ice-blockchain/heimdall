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
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type BalanceUpdateJobArgs struct {
	UserBlockchainAddress string `json:"user_blockchain_address"`
	UserExternalAddress   string `json:"user_external_address"`
	ContractAddress       string `json:"contract_address"`
	TokenExternalAddress  string `json:"token_external_address"`
	TransactionHash       string `json:"transaction_hash"`
	PairID                string `json:"pair_id"`
	BaseToken             string `json:"base_token"`
	TokenType             string `json:"token_type"`

	DummyBalance *string `json:"dummy_balance,omitempty"`
}

func (BalanceUpdateJobArgs) Kind() string {
	return "balance_update"
}

type balanceUpdateWorker struct {
	ta *tokenAnalytics
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

		balance, err = w.ta.bondingCurve.GetTokenBalance(ctx, tokenAddr, userAddr)
		if err != nil {
			return errors.Wrapf(err, "failed to get token balance for user %s token %s",
				args.UserBlockchainAddress, args.ContractAddress)
		}
	}

	_, err = storage.Exec(ctx, w.ta.ingestedDataDB, `
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
	if err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
		return errors.Wrapf(err, "failed to update user token position in DB for user %s token %s",
			args.UserBlockchainAddress, args.ContractAddress)
	}

	userPositionKey := keyUserPositionOfToken(args.TokenExternalAddress)
	userPositionKeyByBlockchainAddress := keyUserPositionOfTokenByUserBlockchainAddress(args.TokenExternalAddress)
	balanceFloat := weiToFloat64FromBigInt(balance)
	if responses, txErr := w.ta.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if balanceFloat <= 0 {
			if args.UserExternalAddress != "" {
				if perr := pipeliner.ZRem(ctx, userPositionKey, args.UserExternalAddress).Err(); perr != nil {
					return errors.Wrapf(perr, "failed to remove user position from Redis for user %s token %s",
						args.UserExternalAddress, args.TokenExternalAddress)
				}
			}
			if perr := pipeliner.ZRem(ctx, userPositionKeyByBlockchainAddress, args.UserBlockchainAddress).Err(); perr != nil {
				return errors.Wrapf(perr, "failed to remove user position from Redis for user %s token %s",
					args.UserBlockchainAddress, args.TokenExternalAddress)
			}
		} else {
			if args.UserExternalAddress != "" {
				if perr := pipeliner.ZAdd(ctx, userPositionKey, redis.Z{
					Score:  balanceFloat,
					Member: args.UserExternalAddress,
				}).Err(); perr != nil {
					return errors.Wrapf(perr, "failed to add user position to Redis for user %s token %s",
						args.UserExternalAddress, args.TokenExternalAddress)
				}
			}
			if perr := pipeliner.ZAdd(ctx, userPositionKeyByBlockchainAddress, redis.Z{
				Score:  balanceFloat,
				Member: args.UserBlockchainAddress,
			}).Err(); perr != nil {
				return errors.Wrapf(perr, "failed to add user position to Redis for user %s token %s",
					args.UserBlockchainAddress, args.TokenExternalAddress)
			}
		}
		return nil
	}); txErr != nil {
		return errors.Wrapf(txErr, "failed to update user positions for user %v(%v): %w", args.UserExternalAddress, args.UserBlockchainAddress)
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil {
				return errors.Wrapf(rerr, "failed to `%v` while updating user positions for user %v(%v): %w", response.FullName(), args.UserExternalAddress, args.UserBlockchainAddress, rerr)
			}
		}
	}

	log.Debug(fmt.Sprintf("Balance updated: user=%s, token=%s, balance=%s",
		args.UserBlockchainAddress, args.TokenExternalAddress, balance.String()))

	if args.PairID == "" || args.BaseToken == "" {
		log.Debug(fmt.Sprintf("Skipping bonding curve update for token=%s: missing pairID (%q) or baseToken (%q)",
			args.TokenExternalAddress, args.PairID, args.BaseToken))
	} else if err := w.updateBondingCurveProgress(ctx, args.TokenExternalAddress, args.PairID, args.BaseToken, args.TokenType, args.DummyBalance != nil); err != nil {
		log.Error(errors.Wrapf(err, "failed to update bonding curve for token %s (balance update succeeded)", args.TokenExternalAddress))
	}

	return nil
}

func (w *balanceUpdateWorker) updateBondingCurveProgress(ctx context.Context, externalAddress, pairID, baseToken, tokenType string, isDummy bool) error {
	var progress *bondingcurve.BondingCurveProgress
	var err error

	if isDummy {
		soldTokens := new(big.Int).SetUint64(uint64(50 + randInt(150))) // 50-200 tokens
		soldTokens.Mul(soldTokens, big.NewInt(1e18))
		tokensRaised := new(big.Int).SetUint64(uint64(5 + randInt(15))) // 5-20 base tokens
		tokensRaised.Mul(tokensRaised, big.NewInt(1e18))
		bondingTokensGoal := new(big.Int).SetUint64(uint64(200 + randInt(300))) // 200-500 tokens
		bondingTokensGoal.Mul(bondingTokensGoal, big.NewInt(1e18))

		progress = &bondingcurve.BondingCurveProgress{
			BondingCurveBondingInfo: &bondingcurve.BondingCurveBondingInfo{
				SoldTokens:        soldTokens,
				TokensRaised:      tokensRaised,
				BondingTokensGoal: bondingTokensGoal,
				Migrated:          false,
			},
			Liquidity: big.NewInt(0),
		}
	} else {
		progress, err = w.ta.bondingCurve.Progress(ctx, common.HexToHash(pairID))
		if err != nil {
			return fmt.Errorf("failed to get curve progress for token %v (pair %v): %w", externalAddress, pairID, err)
		}
	}
	goalUSD, currentRaisedUSD, err := w.ta.progressToUSD(ctx, progress, baseToken)
	if err != nil {
		return fmt.Errorf("failed to calculate progress USD for token %v: %w", externalAddress, err)
	}
	liquidityUSD, _, err := w.ta.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.Liquidity), baseToken)
	if err != nil {
		return fmt.Errorf("failed to calculate liquidity USD for token %v: %w", externalAddress, err)
	}

	_, err = storage.Exec(ctx, w.ta.ingestedDataDB, `
		UPDATE tokens AS t
		SET
		    bonding_curve_current_amount = $2,
		    bonding_curve_raised_amount = $3,
		    bonding_curve_goal_amount = $4,
		    bonding_curve_current_amount_usd = $5,
		    bonding_curve_goal_amount_usd = $6,
		    bonding_curve_migrated = $7,
		    liquidity_usd = $8,
			updated_at = NOW()
		WHERE t.external_address = $1`,
		externalAddress,
		progress.SoldTokens.String(),
		progress.TokensRaised.String(),
		progress.BondingTokensGoal.String(),
		currentRaisedUSD,
		goalUSD,
		progress.Migrated,
		liquidityUSD)

	if err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
		return fmt.Errorf("failed to update bonding curve for token %v: %w", externalAddress, err)
	}

	if !progress.Migrated {
		currentAmountWei := new(big.Float).SetInt(progress.SoldTokens)
		currentAmountScore, _ := currentAmountWei.Float64()

		if err := w.ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{
			Score:  currentAmountScore,
			Member: externalAddress,
		}).Err(); err != nil {
			return errors.Wrapf(err, "failed to update bonding curve progress in Redis for token %s", externalAddress)
		}

		if tokenType != "" {
			if typeSpecificKey := getBondingCurveProgressSetKeyByType(tokenType); typeSpecificKey != "" {
				if err := w.ta.processedDataDB.ZAdd(ctx, typeSpecificKey, redis.Z{
					Score:  currentAmountScore,
					Member: externalAddress,
				}).Err(); err != nil {
					return errors.Wrapf(err, "failed to update type-specific bonding curve progress in Redis for token %s type %s", externalAddress, tokenType)
				}
			}
			if tokenType == TokenTypePost || tokenType == TokenTypeVideo || tokenType == TokenTypeArticle {
				if err := w.ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressAnyPostSetKey, redis.Z{
					Score:  currentAmountScore,
					Member: externalAddress,
				}).Err(); err != nil {
					return errors.Wrapf(err, "failed to update anyPost bonding curve progress in Redis for token %s", externalAddress)
				}
			}
		}
	} else {
		if err := w.ta.processedDataDB.ZRem(ctx, globalBondingCurveProgressSetKey, externalAddress).Err(); err != nil {
			return errors.Wrapf(err, "failed to remove token from bonding curve progress in Redis for token %s", externalAddress)
		}
		if tokenType != "" {
			if typeSpecificKey := getBondingCurveProgressSetKeyByType(tokenType); typeSpecificKey != "" {
				if err := w.ta.processedDataDB.ZRem(ctx, typeSpecificKey, externalAddress).Err(); err != nil {
					return errors.Wrapf(err, "failed to remove token from type-specific bonding curve progress in Redis for token %s type %s", externalAddress, tokenType)
				}
			}
			if tokenType == TokenTypePost || tokenType == TokenTypeVideo || tokenType == TokenTypeArticle {
				if err := w.ta.processedDataDB.ZRem(ctx, globalBondingCurveProgressAnyPostSetKey, externalAddress).Err(); err != nil {
					return errors.Wrapf(err, "failed to remove token from anyPost bonding curve progress in Redis for token %s", externalAddress)
				}
			}
		}
	}

	progressPercent := 0.0
	if goalUSD > 0 {
		progressPercent = (currentRaisedUSD / goalUSD) * 100
	}

	log.Debug(fmt.Sprintf("Updated bonding curve for token %s: progress=%.1f%%, liquidity=$%.2f, current=%s, goal=%s",
		externalAddress, progressPercent, liquidityUSD, progress.SoldTokens.String(), progress.BondingTokensGoal.String()))

	return nil
}
