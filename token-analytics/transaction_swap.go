// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	stderrors "errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onSwap(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped) error {
	contractAddr := strings.ToLower(ev.Address.Hex())
	userAddr := strings.ToLower(ev.Swapper.Hex())

	if err := t.validateTokenBaseToken(ctx, contractAddr); err != nil {
		return fmt.Errorf("failed to validate token base token: %w", err)
	}
	ionPriceUSD := t.ionPriceUSD.Load()
	if ionPriceUSD == nil {
		return fmt.Errorf("ION price not yet synced")
	}

	priceInION := calculatePriceFromSwap(ev) // Price: how much ION per 1 community token
	priceUSD := priceInION * (*ionPriceUSD)

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddr, ev.Direction, priceUSD, *ionPriceUSD, userAddr, tx.TransactionHash))

	return t.calculateTokenMarketData(ctx, tx, contractAddr, userAddr, ev, priceUSD)
}

func (t *tokenAnalytics) calculateTokenMarketData(ctx context.Context, tx *txEvent, contractAddr, userAddr string, ev *bondingcurve.LogTokenSwapped, priceUSD float64) error {
	var tokenAmount *big.Int
	if ev.Direction { // buy
		tokenAmount = ev.OutputAmount // User receives tokens
	} else { // sell
		tokenAmount = ev.InputAmount // User sends tokens
	}
	masterPubkey, err := t.getMasterPubkeyByAddress(ctx, userAddr)
	if err != nil {
		return fmt.Errorf("failed to get master_pubkey for user %v: %w", userAddr, err)
	}
	key := fmt.Sprintf("position:%s", contractAddr)
	oldBalance, err := t.processedDataDB.ZScore(ctx, key, masterPubkey).Result()
	hadBalance := err == nil
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get current dragonfly balance for rollback: %w", err)
	}
	if ev.Direction { // buy
		if err := t.increaseDragonflyUserPosition(ctx, key, masterPubkey, tokenAmount); err != nil {
			return fmt.Errorf("failed to increase dragonfly balance for %v (master_pubkey: %v): %w", userAddr, masterPubkey, err)
		}
	} else { // sell
		if err := t.decreaseDragonflyUserPosition(ctx, key, masterPubkey, tokenAmount); err != nil {
			return fmt.Errorf("failed to decrease dragonfly balance for %v (master_pubkey: %v): %w", userAddr, masterPubkey, err)
		}
	}
	if err := t.saveSwapAndUpdateData(ctx, tx, contractAddr, userAddr, ev, priceUSD); err != nil {
		if rollbackErr := t.rollbackDragonflyPosition(ctx, key, masterPubkey, oldBalance, hadBalance); rollbackErr != nil {
			return stderrors.Join(
				fmt.Errorf("failed to save swap data for tx %v: %w", tx.TransactionHash, err),
				rollbackErr,
			)
		}
		return fmt.Errorf("failed to save swap data for tx %v: %w", tx.TransactionHash, err)
	}

	return nil
}

func (t *tokenAnalytics) rollbackDragonflyPosition(ctx context.Context, key, masterPubkey string, oldBalance float64, hadBalance bool) error {
	if hadBalance {
		member := redis.Z{
			Score:  oldBalance,
			Member: masterPubkey,
		}
		if err := t.processedDataDB.ZAdd(ctx, key, member).Err(); err != nil {
			return fmt.Errorf("failed to rollback dragonfly balance for %v: %w", masterPubkey, err)
		}
	} else {
		if err := t.processedDataDB.ZRem(ctx, key, masterPubkey).Err(); err != nil {
			return fmt.Errorf("failed to rollback dragonfly balance removal for %v: %w", masterPubkey, err)
		}
	}
	return nil
}

func (t *tokenAnalytics) saveSwapAndUpdateData(ctx context.Context, tx *txEvent, contractAddr, userAddr string, ev *bondingcurve.LogTokenSwapped, priceUSD float64) error {
	tokenAmount := ev.OutputAmount

	ionPriceUSD := t.ionPriceUSD.Load()
	if ionPriceUSD == nil {
		return fmt.Errorf("ION price not yet synced")
	}

	costBaseToken := bigIntToFloat(ev.InputAmount)
	costUSD := costBaseToken * (*ionPriceUSD)

	var volumeBaseToken float64
	if ev.Direction { // buy
		volumeBaseToken = bigIntToFloat(ev.InputAmount)
	} else { // sell
		volumeBaseToken = bigIntToFloat(ev.OutputAmount)
	}
	marketCapDelta := volumeBaseToken * (*ionPriceUSD)
	if !ev.Direction { // sell
		marketCapDelta = -marketCapDelta
	}
	positionCTE := ""
	args := []interface{}{
		tx.BlockTimestamp,
		tx.TransactionHash,
		contractAddr,
		userAddr,
		ev.Direction,
		ev.InputAmount.String(),
		ev.OutputAmount.String(),
		priceUSD,
		priceUSD,
		marketCapDelta,
		tokenAmount.String(),
	}

	if ev.Direction { // BUY
		positionCTE = `upsert_position AS (
			INSERT INTO user_token_positions (
				master_pubkey, contract_address, amount, 
				avg_buy_price_usd, total_invested_usd, updated_at
			) VALUES ($4, $3, $11, $9, $12, NOW())
			ON CONFLICT (master_pubkey, contract_address) DO UPDATE SET
				amount = user_token_positions.amount + EXCLUDED.amount,
				total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
				avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) / 
									NULLIF((user_token_positions.amount + EXCLUDED.amount)::NUMERIC, 0),
				updated_at = EXCLUDED.updated_at
			RETURNING 1
		)`
		args = append(args, costUSD)
	} else { // SELL
		positionCTE = `update_position AS (
			UPDATE user_token_positions 
			SET 
				amount = GREATEST(amount - $11, 0),
				updated_at = NOW()
			WHERE master_pubkey = $4 AND contract_address = $3
			RETURNING 1
		)`
	}

	query := `
	WITH insert_swap AS (
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, user_address,
			direction, input_amount, output_amount, price_usd
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (transaction_hash, contract_address, user_address) DO NOTHING
		RETURNING 1
	),
	update_market AS (
		UPDATE tokens
		SET 
			price_usd = $9,
			market_cap_usd = GREATEST(market_cap_usd + $10, 0),
			updated_at = NOW()
		WHERE contract_address = $3
		RETURNING 1
	),
	` + positionCTE + `
	SELECT 1`

	_, err := storage.Exec(ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return fmt.Errorf("failed to execute swap CTEs: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) increaseDragonflyUserPosition(ctx context.Context, key, holderAddr string, amount *big.Int) error {
	currentScore, err := t.processedDataDB.ZScore(ctx, key, holderAddr).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get current score for %v: %w", holderAddr, err)
	}
	newBalance := currentScore + bigIntToFloat(amount)
	member := redis.Z{
		Score:  newBalance,
		Member: holderAddr,
	}

	return t.processedDataDB.ZAdd(ctx, key, member).Err()
}

func (t *tokenAnalytics) decreaseDragonflyUserPosition(ctx context.Context, key, holderAddr string, amount *big.Int) error {
	currentScore, err := t.processedDataDB.ZScore(ctx, key, holderAddr).Result()
	if err != nil && !stderrors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get current score for %v: %w", holderAddr, err)
	}
	newBalance := currentScore - bigIntToFloat(amount)
	if newBalance < 0 {
		newBalance = 0
	}
	if newBalance > 0 {
		member := redis.Z{
			Score:  newBalance,
			Member: holderAddr,
		}
		return t.processedDataDB.ZAdd(ctx, key, member).Err()
	}

	return t.processedDataDB.ZRem(ctx, key, holderAddr).Err()
}

func calculatePriceFromSwap(ev *bondingcurve.LogTokenSwapped) float64 {
	// Price calculation: how much base token per 1 community token
	// For buy: price = input (base token) / output (community tokens)
	// For sell: price = output (base token) / input (community tokens)
	inputFloat := bigIntToFloat(ev.InputAmount)
	outputFloat := bigIntToFloat(ev.OutputAmount)

	if ev.Direction { // buy
		if outputFloat > 0 {
			return inputFloat / outputFloat
		}
	} else { // sell
		if inputFloat > 0 {
			return outputFloat / inputFloat
		}
	}

	return 0
}

func (t *tokenAnalytics) validateTokenBaseToken(ctx context.Context, contractAddr string) error {
	type baseTokenCheck struct {
		BaseToken string `db:"base_token"`
	}
	rows, err := storage.Select[baseTokenCheck](ctx, t.ingestedDataDB,
		`SELECT COALESCE(base_token, '') as base_token FROM tokens WHERE contract_address = $1`,
		contractAddr)
	if err != nil {
		return fmt.Errorf("failed to check base_token for %v: %w", contractAddr, err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("token %v not found in database", contractAddr)
	}

	expectedIONAddress := strings.ToLower(t.cfg.IONTokenAddress)
	actualBaseToken := strings.ToLower(rows[0].BaseToken)

	if actualBaseToken == "" || actualBaseToken != expectedIONAddress {
		return fmt.Errorf("token %v uses invalid base_token %v, expected ION token %v, swap rejected",
			contractAddr, actualBaseToken, expectedIONAddress)
	}

	return nil
}
