// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
	"github.com/ice-blockchain/wintr/time"
)

type BalanceUpdateJobArgs struct {
	UserBlockchainAddress string   `json:"user_blockchain_address"`
	UserExternalAddress   string   `json:"user_external_address"`
	ContractAddress       string   `json:"contract_address"`
	TokenExternalAddress  string   `json:"token_external_address"`
	TransactionHash       string   `json:"transaction_hash"`
	BlockNumber           uint64   `json:"block_number"`
	PairID                string   `json:"pair_id"`
	BaseToken             string   `json:"base_token"`
	TokenType             string   `json:"token_type"`
	Burned                *big.Int `json:"burned"`
	Platform              string   `json:"platform"`
	Ticker                string   `json:"ticker"`

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
	if err := w.ta.setUserPosition(ctx, args.UserBlockchainAddress, args.ContractAddress, args.TokenExternalAddress, args.UserExternalAddress, balance, args.BlockNumber, args.TransactionHash); err != nil {
		return errors.Wrapf(err, "failed to update user token position for user %s token %s %s",
			args.UserBlockchainAddress, args.ContractAddress, args.TokenExternalAddress)
	}
	if args.PairID == "" || args.BaseToken == "" {
		log.Debug(fmt.Sprintf("Skipping bonding curve update for token=%s: missing pairID (%q) or baseToken (%q)",
			args.TokenExternalAddress, args.PairID, args.BaseToken))
	} else if priceUSD, marketCapUSD, err := w.updateBondingCurveProgress(ctx, args.ContractAddress, args.TokenExternalAddress, args.PairID, args.BaseToken, args.TokenType, args.Platform, args.Ticker, args.Burned, args.DummyBalance != nil); err != nil {
		log.Error(errors.Wrapf(err, "failed to update bonding curve for token %s (balance update succeeded)", args.TokenExternalAddress))
	} else {
		if _, err := storage.Exec(ctx, w.ta.ingestedDataDB, `
			UPDATE token_swaps
			SET curve_price_usd = $1,
			    notified_at = NOW()
			WHERE transaction_hash = $2 AND contract_address = $3 AND user_blockchain_address = $4
		`, priceUSD, args.TransactionHash, args.ContractAddress, args.UserBlockchainAddress); err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
			log.Error(errors.Wrapf(err, "failed to update curve_price_usd for tx %s", args.TransactionHash))
		}

		if err := w.registerTradeFromJob(ctx, args, priceUSD, marketCapUSD); err != nil {
			log.Error(errors.Wrapf(err, "failed to register trade for tx %s", args.TransactionHash))
		}
	}
	return nil
}

func (t *tokenAnalytics) setUserPosition(ctx context.Context, userBlockchainAddress, contractAddress,
	tokenExternalAddress, userExternalAddress string, balance *big.Int, blockNum uint64, txHash string) error {
	return t.setOrIncrUserPosition(ctx, userBlockchainAddress, contractAddress, tokenExternalAddress, userExternalAddress, balance, blockNum, txHash,
		"amount = EXCLUDED.amount,",
		func(ctx context.Context, p redis.Pipeliner, key, userKey string, balance float64) redis.Cmder {
			return p.ZAdd(ctx, key, redis.Z{
				Score:  balance,
				Member: userKey,
			})
		})
}

func (t *tokenAnalytics) incrUserPosition(ctx context.Context, userBlockchainAddress, contractAddress,
	tokenExternalAddress, userExternalAddress string, balance *big.Int, blockNum uint64, txHash string) error {
	return t.setOrIncrUserPosition(ctx, userBlockchainAddress, contractAddress, tokenExternalAddress, userExternalAddress, balance, blockNum, txHash,
		"amount = user_token_positions.amount + EXCLUDED.amount,",
		func(ctx context.Context, p redis.Pipeliner, key, userKey string, balance float64) redis.Cmder {
			return p.ZIncrBy(ctx, key, balance, userKey)
		})
}

func (t *tokenAnalytics) decrUserPosition(ctx context.Context, userBlockchainAddress, contractAddress,
	tokenExternalAddress, userExternalAddress string, balance *big.Int, blockNum uint64, txHash string) error {
	return t.setOrIncrUserPosition(ctx, userBlockchainAddress, contractAddress, tokenExternalAddress, userExternalAddress, balance, blockNum, txHash,
		"amount = GREATEST(user_token_positions.amount - EXCLUDED.amount, 0::NUMERIC),",
		func(ctx context.Context, p redis.Pipeliner, key, userKey string, balance float64) redis.Cmder {
			return p.ZIncrBy(ctx, key, -balance, userKey)
		})
}

func (t *tokenAnalytics) setOrIncrUserPosition(ctx context.Context, userBlockchainAddress, contractAddress,
	tokenExternalAddress, userExternalAddress string, balance *big.Int, blockNum uint64, txHash string,
	sqlUpdateClause string,
	zAddOrIncr func(ctx context.Context, p redis.Pipeliner, redisKey, userKey string, balance float64) redis.Cmder) error {
	rowsUpdated, err := storage.Exec(ctx, t.ingestedDataDB, fmt.Sprintf(`
		INSERT INTO user_token_positions (
			user_blockchain_address, contract_address, external_address, user_external_address,
			amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, updated_at, balance_notified_at,
		    last_update_block, last_update_tx_hash
		)
		VALUES (
			$1, $2, $3, $4,
			$5, 0, 0, 0, NOW(), NOW(), $6, $7
		)
		ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
			%[1]v
			updated_at = EXCLUDED.updated_at,
		    last_update_block = excluded.last_update_block,
		    last_update_tx_hash = excluded.last_update_tx_hash,                  
			balance_notified_at = EXCLUDED.balance_notified_at
		WHERE user_token_positions.last_update_block <= $6 and user_token_positions.last_update_tx_hash != $7;
	`, sqlUpdateClause), userBlockchainAddress, contractAddress, tokenExternalAddress,
		userExternalAddress, balance.String(), blockNum, txHash)
	if err == nil && rowsUpdated == 0 {
		log.Debug(fmt.Sprintf("Duplicated call for balance update: user=%s, token=%s, balance=%s tx=%s block=%v",
			userBlockchainAddress, tokenExternalAddress, balance.String(), txHash, blockNum))
		return nil
	}
	if err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
		return errors.Wrapf(err, "failed to update user token position in DB for user/pool %s %s token %s",
			userBlockchainAddress, userExternalAddress, contractAddress)
	}

	userPositionKey := keyUserPositionOfToken(tokenExternalAddress)
	userPositionKeyByBlockchainAddress := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddress)
	balanceFloat := weiToFloat64FromBigInt(balance)
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if balanceFloat <= 0 {
			if userExternalAddress != "" {
				if perr := pipeliner.ZRem(ctx, userPositionKey, userExternalAddress).Err(); perr != nil {
					return errors.Wrapf(perr, "failed to remove user position from Redis for user %s token %s",
						userExternalAddress, tokenExternalAddress)
				}
			}
			if perr := pipeliner.ZRem(ctx, userPositionKeyByBlockchainAddress, userBlockchainAddress).Err(); perr != nil {
				return errors.Wrapf(perr, "failed to remove user position from Redis for user %s token %s",
					userBlockchainAddress, tokenExternalAddress)
			}
		} else {
			if userExternalAddress != "" {
				if perr := zAddOrIncr(ctx, pipeliner, userPositionKey, userExternalAddress, balanceFloat).Err(); perr != nil {
					return errors.Wrapf(perr, "failed to add user position to Redis for user %s token %s",
						userExternalAddress, tokenExternalAddress)
				}
			}
			if perr := zAddOrIncr(ctx, pipeliner, userPositionKeyByBlockchainAddress, userBlockchainAddress, balanceFloat).Err(); perr != nil {
				return errors.Wrapf(perr, "failed to add user position to Redis for user %s token %s",
					userBlockchainAddress, tokenExternalAddress)
			}
		}
		return nil
	}); txErr != nil {
		return errors.Wrapf(txErr, "failed to update user positions for user %v(%v): %w", userExternalAddress, userBlockchainAddress)
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil {
				return errors.Wrapf(rerr, "failed to `%v` while updating user positions for user %v(%v): %w", response.FullName(), userExternalAddress, userBlockchainAddress, rerr)
			}
		}
	}

	log.Debug(fmt.Sprintf("Balance updated: user=%s, token=%s, balance=%s",
		userBlockchainAddress, tokenExternalAddress, balance.String()))

	return nil
}

func (w *balanceUpdateWorker) updateBondingCurveProgress(ctx context.Context, contractAddress, externalAddress, pairID, baseToken, tokenType, platform, symbol string, burned *big.Int, isDummy bool) (float64, float64, error) {
	var progress *bondingcurve.BondingCurveProgress
	var err error

	if isDummy {
		soldTokens := new(big.Int).SetUint64(uint64(50 + randInt(150))) // 50-200 tokens
		soldTokens.Mul(soldTokens, big.NewInt(1e18))
		tokensRaised := new(big.Int).SetUint64(uint64(5 + randInt(15))) // 5-20 base tokens
		tokensRaised.Mul(tokensRaised, big.NewInt(1e18))
		bondingTokensGoal := new(big.Int).SetUint64(uint64(200 + randInt(300))) // 200-500 tokens
		bondingTokensGoal.Mul(bondingTokensGoal, big.NewInt(1e18))
		startPrice := new(big.Int).SetUint64(uint64(1000000000000000000))
		endPrice := new(big.Int).SetUint64(uint64(1000000000000000000))
		progress = &bondingcurve.BondingCurveProgress{
			BondingCurveBondingInfo: &bondingcurve.BondingCurveBondingInfo{
				SoldTokens:        soldTokens,
				TokensRaised:      tokensRaised,
				BondingTokensGoal: bondingTokensGoal,
				StartPrice:        startPrice,
				EndPrice:          endPrice,
				CurrentPrice:      new(big.Int).SetUint64(uint64(1e18)),
				Migrated:          false,
			},
			Liquidity: big.NewInt(0),
		}
	} else {
		progress, err = w.ta.bondingCurve.Progress(ctx, common.HexToHash(pairID))
		if err != nil {
			return 0, 0, fmt.Errorf("failed to get curve progress for token %v (pair %v): %w", externalAddress, pairID, err)
		}
	}
	goalUSD, currentRaisedUSD, err := w.ta.progressToUSD(ctx, progress, baseToken)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate progress USD for token %v: %w", externalAddress, err)
	}
	liquidityUSD, _, err := w.ta.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.Liquidity), baseToken)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate liquidity USD for token %v: %w", externalAddress, err)
	}
	currentPriceUSD, _, err := w.ta.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.CurrentPrice), baseToken)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate current price USD for token %v (base %v): %w", externalAddress, baseToken, err)
	}

	burnedAmount := burned
	if burnedAmount == nil {
		burnedAmount = big.NewInt(0)
	}

	mCapUSDF := marketCap(currentPriceUSD, progress.BondingTokensGoal, burnedAmount)
	mCapUSD, _ := mCapUSDF.Float64()
	ionPrice := w.ta.ionPriceUSD.Load()
	mCapION := mCapUSD / *ionPrice
	_, err = storage.Exec(ctx, w.ta.ingestedDataDB, `
		UPDATE tokens AS t
		SET
		    bonding_curve_current_amount = $2,
		    bonding_curve_raised_amount = $3,
		    bonding_curve_goal_amount = $4,
		    bonding_curve_current_amount_usd = $5,
		    bonding_curve_goal_amount_usd = $6,
		    bonding_curve_migrated = $7,
		    migrated_at = CASE WHEN $7 = true AND t.bonding_curve_migrated = false THEN NOW() ELSE t.migrated_at END,
		    liquidity_usd = $8,
		    start_price = $9,
		    end_price = $10,
		    price_usd = $11,
		    market_cap_usd = $12,
		    market_cap = $13,
			updated_at = NOW()
		WHERE t.external_address = $1`,
		externalAddress,
		progress.SoldTokens.String(),
		progress.TokensRaised.String(),
		progress.BondingTokensGoal.String(),
		currentRaisedUSD,
		goalUSD,
		progress.Migrated,
		liquidityUSD,
		progress.StartPrice.String(),
		progress.EndPrice.String(),
		currentPriceUSD,
		mCapUSD,
		mCapION,
	)

	if err != nil && !storage.IsErr(err, storage.ErrReadOnly) {
		return 0, 0, fmt.Errorf("failed to update bonding curve for token %v: %w", externalAddress, err)
	}

	currentAmountWei := new(big.Float).SetInt(progress.SoldTokens)
	currentAmountScore, _ := currentAmountWei.Float64()

	if err := w.ta.updateBondingCurveInRedis(ctx, externalAddress, tokenType, platform, currentAmountScore, progress.Migrated); err != nil {
		return 0, 0, errors.Wrapf(err, "failed to update bonding curve in Redis for token %s", externalAddress)
	}
	progressPercent := 0.0
	if goalUSD > 0 {
		progressPercent = (currentRaisedUSD / goalUSD) * 100
	}
	if tokenType == TokenTypeProfile {
		if err = saveBaseTokenPriceToDatabase(ctx, w.ta.ingestedDataDB, symbol, contractAddress, currentPriceUSD, progress.CurrentPrice); err != nil {
			return 0, 0, errors.Wrapf(err, "failed to save base token price to database for token %s", externalAddress)
		}
	}
	log.Debug(fmt.Sprintf("Updated bonding curve for token %s: progress=%.1f%%, liquidity=$%.2f, current=%s, goal=%s",
		externalAddress, progressPercent, liquidityUSD, progress.SoldTokens.String(), progress.BondingTokensGoal.String()))

	return currentPriceUSD, mCapUSD, nil
}

func (t *tokenAnalytics) updateBondingCurveInRedis(ctx context.Context, externalAddress, tokenType, platform string, currentAmountScore float64, migrated bool) error {
	if !migrated {
		if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{
			Score:  currentAmountScore,
			Member: externalAddress,
		}).Err(); err != nil {
			return errors.Wrap(err, "failed to update bonding curve progress in Redis")
		}

		if platform == PlatformGroupXCom {
			if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressXcomSetKey, redis.Z{
				Score:  currentAmountScore,
				Member: externalAddress,
			}).Err(); err != nil {
				return errors.Wrap(err, "failed to update xcom bonding curve progress in Redis")
			}
		}
		if tokenType != "" {
			if typeSpecificKey := getBondingCurveProgressSetKeyByType(tokenType); typeSpecificKey != "" {
				if err := t.processedDataDB.ZAdd(ctx, typeSpecificKey, redis.Z{
					Score:  currentAmountScore,
					Member: externalAddress,
				}).Err(); err != nil {
					return errors.Wrapf(err, "failed to update type-specific bonding curve progress in Redis for type %s", tokenType)
				}
			}
			if tokenType == TokenTypePost || tokenType == TokenTypeVideo || tokenType == TokenTypeArticle {
				if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressAnyPostSetKey, redis.Z{
					Score:  currentAmountScore,
					Member: externalAddress,
				}).Err(); err != nil {
					return errors.Wrap(err, "failed to update anyPost bonding curve progress in Redis")
				}
			}
		}
	} else {
		if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressSetKey, externalAddress).Err(); err != nil {
			return errors.Wrap(err, "failed to remove token from bonding curve progress in Redis")
		}
		if platform == PlatformGroupXCom {
			if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressXcomSetKey, externalAddress).Err(); err != nil {
				return errors.Wrap(err, "failed to remove token from xcom bonding curve progress in Redis")
			}
		}
		if tokenType != "" {
			if typeSpecificKey := getBondingCurveProgressSetKeyByType(tokenType); typeSpecificKey != "" {
				if err := t.processedDataDB.ZRem(ctx, typeSpecificKey, externalAddress).Err(); err != nil {
					return errors.Wrapf(err, "failed to remove token from type-specific bonding curve progress in Redis for type %s", tokenType)
				}
			}
			if tokenType == TokenTypePost || tokenType == TokenTypeVideo || tokenType == TokenTypeArticle {
				if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressAnyPostSetKey, externalAddress).Err(); err != nil {
					return errors.Wrap(err, "failed to remove token from anyPost bonding curve progress in Redis")
				}
			}
		}
	}

	return nil
}

func (w *balanceUpdateWorker) registerTradeFromJob(ctx context.Context, args BalanceUpdateJobArgs, priceUSD, marketCapUSD float64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("panic in registerTradeFromJob for tx %s: %v", args.TransactionHash, r)
			log.Error(err)
		}
	}()

	type swapData struct {
		Direction    bool            `db:"direction"`
		InputAmount  string          `db:"input_amount"`
		OutputAmount string          `db:"output_amount"`
		CreatedAt    stdlibtime.Time `db:"created_at"`
		TotalSupply  string          `db:"total_supply"`
	}

	swap, err := storage.Get[swapData](ctx, w.ta.ingestedDataDB, `
		SELECT 
				ts.direction,
				ts.input_amount,
				ts.output_amount,
				ts.created_at,
		        t.total_supply
		FROM token_swaps ts
		JOIN tokens t ON t.contract_address = ts.contract_address
		WHERE ts.transaction_hash = $1 AND ts.contract_address = $2 AND ts.user_blockchain_address = $3
	`, args.TransactionHash, args.ContractAddress, args.UserBlockchainAddress)

	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			log.Error(errors.Wrapf(err, "Swap not found for tx %s, contract %s, user %s",
				args.TransactionHash, args.ContractAddress, args.UserBlockchainAddress))

			return nil
		}

		return errors.Wrapf(err, "failed to get swap data for tx %s", args.TransactionHash)
	}
	inputAmount := new(big.Int)
	inputAmount.SetString(swap.InputAmount, 10)
	outputAmount := new(big.Int)
	outputAmount.SetString(swap.OutputAmount, 10)
	totalSupply := new(big.Int)
	totalSupply.SetString(swap.TotalSupply, 10)
	pairIdBytes, _ := hex.DecodeString(strings.TrimPrefix(args.PairID, "0x"))

	burned := args.Burned
	if burned == nil {
		burned = big.NewInt(0)
	}

	tx := &txEvent{
		TransactionHash: args.TransactionHash,
		BlockNumber:     args.BlockNumber,
		BlockTimestamp:  time.New(swap.CreatedAt),
	}
	if err := w.ta.registerTrade(ctx, tx, swap.Direction, inputAmount, outputAmount,
		args.ContractAddress, args.UserBlockchainAddress, args.TokenExternalAddress,
		args.BaseToken, pairIdBytes, totalSupply, burned, priceUSD, marketCapUSD); err != nil {
		return err
	}
	tradeInfo, err := w.ta.fetchTradeInfoFromSwap(ctx, args.TransactionHash, args.ContractAddress, args.UserBlockchainAddress)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v contract %v user %v to notify subscribers",
			args.TransactionHash, args.ContractAddress, args.UserBlockchainAddress))

		return
	}

	log.Debug(fmt.Sprintf("[BALANCE_JOB->NOTIFY_SWAP] tx=%s, external_address=%s, direction=%v, input=%s, output=%s, price_usd=%.6f, mcap_usd=%.2f",
		args.TransactionHash, tradeInfo.TokenExternalAddress, swap.Direction, swap.InputAmount, swap.OutputAmount, priceUSD, marketCapUSD))

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error(errors.Errorf("panic in NotifySwap goroutine for tx %s: %v", args.TransactionHash, r))
			}
		}()

		w.ta.subscriptions.NotifySwap(tradeInfo)
	}()

	return nil
}
