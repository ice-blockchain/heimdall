// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onSwap(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped) error {
	userAddr := strings.ToLower(ev.Swapper.Hex())

	ionConnectAddressParam, ok := ev.Params["toToken"]
	if !ok {
		return fmt.Errorf("failed to extract ion_connect_address from tx.Input: toToken param not found")
	}
	ionConnectAddressBytes, ok := ionConnectAddressParam.([]byte)
	if !ok {
		return fmt.Errorf("failed to extract ion_connect_address from tx.Input: toToken is not bytes")
	}
	ionConnectAddress := string(ionConnectAddressBytes)
	type tokenByIonConnect struct {
		ContractAddress string `db:"contract_address"`
	}
	result, err := storage.Get[tokenByIonConnect](ctx, t.ingestedDataDB, `
		SELECT contract_address FROM tokens WHERE ion_connect_address = $1
	`, ionConnectAddress)
	if err != nil {
		return fmt.Errorf("failed to find token by ion_connect_address %v: %w", ionConnectAddress, err)
	}
	contractAddress := result.ContractAddress
	log.Debug(fmt.Sprintf("onSwap: ionConnect=%s, contractAddress=%s", ionConnectAddress, contractAddress))

	type tokenResult struct {
		BaseToken string `db:"base_token"`
	}
	tokenInfo, err := storage.Get[tokenResult](ctx, t.ingestedDataDB, `
		SELECT COALESCE(base_token, '') as base_token 
		FROM tokens WHERE contract_address = $1
	`, contractAddress)
	if err != nil {
		return fmt.Errorf("failed to find token by contract_address %v: %w", contractAddress, err)
	}

	expectedIONAddress := strings.ToLower(t.cfg.IONTokenAddress)
	actualBaseToken := strings.ToLower(tokenInfo.BaseToken)
	if actualBaseToken == "" || actualBaseToken != expectedIONAddress {
		return fmt.Errorf("token %v uses invalid base_token %v, expected ION token %v, swap rejected",
			contractAddress, actualBaseToken, expectedIONAddress)
	}

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, userAddr=%s", contractAddress, userAddr))

	if err := t.registerTrade(ctx, tx, ev, ionConnectAddress); err != nil {
		return fmt.Errorf("failed to save trade in questdb %v ]]: %w", userAddr, err)
	}
	ionPriceUSD := t.ionPriceUSD.Load()

	priceInION := calculatePriceFromSwap(ev) // Price: how much ION per 1 community token
	priceUSD := priceInION * (*ionPriceUSD)

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddress, ev.Direction, priceUSD, *ionPriceUSD, userAddr, tx.TransactionHash))

	return t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, userAddr, ev, priceUSD)
}

func (t *tokenAnalytics) calculateTokenMarketDataAndUserPosition(ctx context.Context, tx *txEvent, contractAddress, userAddr string, ev *bondingcurve.LogTokenSwapped, priceUSD float64) error {
	var tokenAmount *big.Int
	var sign float64
	if !ev.Direction { // buy (Direction=false)
		tokenAmount = ev.OutputAmount // User receives tokens
		sign = 1.0
	} else { // sell (Direction=true)
		tokenAmount = ev.InputAmount // User sends tokens
		sign = -1.0
	}
	deltaMarketCapUSD := sign * bigIntToFloat(tokenAmount) * priceUSD
	tokenIonConnectAddress, userIonConnectAddress, err := t.saveSwapAndUpdateData(ctx, tx, contractAddress, userAddr, ev, priceUSD, deltaMarketCapUSD)
	if err != nil {
		return fmt.Errorf("failed to save swap data: %w", err)
	}
	userPostitionKey := keyUserPositionOfToken(tokenIonConnectAddress)
	if !ev.Direction { // buy (Direction=false)
		if err := t.increaseDragonflyUserPosition(ctx, userPostitionKey, userIonConnectAddress, tokenAmount); err != nil {
			if rollbackErr := t.rollbackPostgreSQLSwap(ctx, tx.TransactionHash, contractAddress); rollbackErr != nil {
				return errors.Join(
					fmt.Errorf("failed to increase dragonfly balance: %w", err),
					rollbackErr,
				)
			}

			return fmt.Errorf("failed to increase dragonfly balance for %v (user ion_connect: %v): %w", userAddr, userIonConnectAddress, err)
		}
	} else { // sell
		if err := t.decreaseDragonflyUserPosition(ctx, userPostitionKey, userIonConnectAddress, tokenAmount); err != nil {
			if rollbackErr := t.rollbackPostgreSQLSwap(ctx, tx.TransactionHash, contractAddress); rollbackErr != nil {
				return errors.Join(
					fmt.Errorf("failed to decrease dragonfly balance: %w", err),
					rollbackErr,
				)
			}

			return fmt.Errorf("failed to decrease dragonfly balance for %v (user ion_connect: %v): %w", userAddr, userIonConnectAddress, err)
		}
	}

	if err := t.processedDataDB.ZIncrBy(ctx, globalTopSetKey, deltaMarketCapUSD, tokenIonConnectAddress).Err(); err != nil {
		if !ev.Direction { // was buy (Direction=false) → rollback with decrease
			if rollbackErr := t.decreaseDragonflyUserPosition(ctx, userPostitionKey, userIonConnectAddress, tokenAmount); rollbackErr != nil {
				return errors.Join(
					fmt.Errorf("failed to update market cap: %w", err),
					fmt.Errorf("failed to rollback user position: %w", rollbackErr),
				)
			}
		} else { // was sell → rollback with increase
			if rollbackErr := t.increaseDragonflyUserPosition(ctx, userPostitionKey, userIonConnectAddress, tokenAmount); rollbackErr != nil {
				return errors.Join(
					fmt.Errorf("failed to update market cap: %w", err),
					fmt.Errorf("failed to rollback user position: %w", rollbackErr),
				)
			}
		}
		if rollbackErr := t.rollbackPostgreSQLSwap(ctx, tx.TransactionHash, contractAddress); rollbackErr != nil {
			return errors.Join(
				fmt.Errorf("failed to save swap data for tx %v: %w", tx.TransactionHash, err),
				rollbackErr,
			)
		}
		return fmt.Errorf("failed to save swap data for tx %v: %w", tx.TransactionHash, err)
	}

	return nil
}

func (t *tokenAnalytics) rollbackPostgreSQLSwap(ctx context.Context, txHash, contractAddress string) error {
	query := `DELETE FROM token_swaps WHERE transaction_hash = $1 AND contract_address = $2`
	if _, err := t.ingestedDataDB.Exec(ctx, query, txHash, contractAddress); err != nil {
		return fmt.Errorf("failed to rollback PostgreSQL swap for tx %v: %w", txHash, err)
	}

	return nil
}

func (t *tokenAnalytics) saveSwapAndUpdateData(ctx context.Context, tx *txEvent, contractAddress, userAddr string, ev *bondingcurve.LogTokenSwapped, priceUSD, deltaMarketCapUSD float64) (tokenIonConnectAddress, userIonConnectAddress string, err error) {
	log.Debug(fmt.Sprintf("saveSwapAndUpdateData: tx=%s, contractAddress=%s, userAddr=%s", tx.TransactionHash, contractAddress, userAddr))

	ionPriceUSD := t.ionPriceUSD.Load()
	if ionPriceUSD == nil {
		return "", "", fmt.Errorf("ION price not yet synced")
	}

	costBaseToken := bigIntToFloat(ev.InputAmount)
	costUSD := costBaseToken * (*ionPriceUSD)

	var positionCTE string
	var args []interface{}

	if !ev.Direction { // BUY (Direction=false means buy)
		args = []interface{}{
			contractAddress,          // $1
			tx.BlockTimestamp,        // $2
			tx.TransactionHash,       // $3
			userAddr,                 // $4
			ev.Direction,             // $5
			ev.InputAmount.String(),  // $6
			ev.OutputAmount.String(), // $7
			priceUSD,                 // $8
			deltaMarketCapUSD,        // $9
			ev.OutputAmount.String(), // $10 (amount for position)
			costUSD,                  // $11 (total_invested_usd)
		}
		positionCTE = `upsert_position AS (
			INSERT INTO user_token_positions (
				master_pubkey, contract_address, ion_connect_address, amount, 
				avg_buy_price_usd, total_invested_usd, updated_at
			) 
			SELECT ui.user_master_pubkey, ti.contract_address, ti.token_ion_connect, $10, $8, $11, NOW()
			FROM token_info ti, user_info ui
			ON CONFLICT (master_pubkey, contract_address) DO UPDATE SET
				amount = user_token_positions.amount + EXCLUDED.amount,
				total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
				avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) / 
									NULLIF((user_token_positions.amount + EXCLUDED.amount)::NUMERIC, 0),
				updated_at = EXCLUDED.updated_at
			RETURNING 1
		)`
	} else { // SELL
		args = []interface{}{
			contractAddress,          // $1
			tx.BlockTimestamp,        // $2
			tx.TransactionHash,       // $3
			userAddr,                 // $4
			ev.Direction,             // $5
			ev.InputAmount.String(),  // $6
			ev.OutputAmount.String(), // $7
			priceUSD,                 // $8
			deltaMarketCapUSD,        // $9
			ev.InputAmount.String(),  // $10 (amount to subtract)
		}
		positionCTE = `update_position AS (
			UPDATE user_token_positions 
			SET 
				amount = GREATEST(amount - $10, 0),
				updated_at = NOW()
			FROM token_info ti, user_info ui
			WHERE user_token_positions.master_pubkey = ui.user_master_pubkey 
				AND user_token_positions.contract_address = ti.contract_address
			RETURNING 1
		)`
	}

	query := `
	WITH token_info AS (
		SELECT 
			contract_address,
			ion_connect_address as token_ion_connect
		FROM tokens
		WHERE contract_address = $1
	),
	user_info AS (
		SELECT 
			COALESCE(ion_connect_address, '') as user_ion_connect,
			master_pubkey as user_master_pubkey
		FROM users
		WHERE LOWER(blockchain_address) = LOWER($4)
	),
	insert_swap AS (
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, ion_connect_address, user_address,
			direction, input_amount, output_amount, price_usd
		)
		SELECT $2, $3, contract_address, token_ion_connect, $4, $5, $6, $7, $8
		FROM token_info
		ON CONFLICT (transaction_hash, contract_address, user_address) DO NOTHING
		RETURNING 1
	),
	update_market AS (
		UPDATE tokens
		SET 
			price_usd = $8,
			market_cap_usd = GREATEST(market_cap_usd + $9, 0),
			updated_at = NOW()
		FROM token_info
		WHERE tokens.contract_address = token_info.contract_address
		RETURNING 1
	),
	` + positionCTE + `
	SELECT ti.token_ion_connect as token_ion_connect, COALESCE(ui.user_ion_connect, '') as user_ion_connect 
	FROM token_info ti
	LEFT JOIN user_info ui ON TRUE`

	type result struct {
		TokenIonConnect string `db:"token_ion_connect"`
		UserIonConnect  string `db:"user_ion_connect"`
	}

	results, err := storage.Select[result](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return "", "", fmt.Errorf("failed to execute swap CTEs: %w", err)
	}
	if len(results) == 0 {
		return "", "", fmt.Errorf("token with contract_address %s not found", contractAddress)
	}

	tokenIonConnectAddress = results[0].TokenIonConnect
	userIonConnectAddress = results[0].UserIonConnect

	log.Debug(fmt.Sprintf("Saved swap: contractAddress=%s, tokenIonConnect=%s, userIonConnect=%s",
		contractAddress, tokenIonConnectAddress, userIonConnectAddress))

	return tokenIonConnectAddress, userIonConnectAddress, nil
}

func (t *tokenAnalytics) increaseDragonflyUserPosition(ctx context.Context, key, userIonConnect string, amount *big.Int) error {
	currentScore, err := t.processedDataDB.ZScore(ctx, key, userIonConnect).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get current balance: %w", err)
	}
	amountFloat := bigIntToFloat(amount)
	newScore := currentScore + amountFloat

	if err := t.processedDataDB.ZAdd(ctx, key, redis.Z{
		Score:  newScore,
		Member: userIonConnect,
	}).Err(); err != nil {
		return fmt.Errorf("failed to increase balance: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) decreaseDragonflyUserPosition(ctx context.Context, key, userIonConnect string, amount *big.Int) error {
	currentScore, err := t.processedDataDB.ZScore(ctx, key, userIonConnect).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// User doesn't have this position, treat as 0
			return nil
		}
		return fmt.Errorf("failed to get current balance: %w", err)
	}
	amountFloat := bigIntToFloat(amount)
	newScore := currentScore - amountFloat

	if newScore <= 0 {
		if err := t.processedDataDB.ZRem(ctx, key, userIonConnect).Err(); err != nil {
			return fmt.Errorf("failed to remove holder: %w", err)
		}
	} else {
		if err := t.processedDataDB.ZAdd(ctx, key, redis.Z{
			Score:  newScore,
			Member: userIonConnect,
		}).Err(); err != nil {
			return fmt.Errorf("failed to decrease balance: %w", err)
		}
	}

	return nil
}

func calculatePriceFromSwap(ev *bondingcurve.LogTokenSwapped) float64 {
	inputAmount := bigIntToFloat(ev.InputAmount)
	outputAmount := bigIntToFloat(ev.OutputAmount)

	if outputAmount == 0 {
		return 0
	}

	if !ev.Direction { // buy (Direction=false): user sends base tokens, receives community tokens
		return inputAmount / outputAmount // base tokens per community token
	}
	// sell (Direction=true): user sends community tokens, receives base tokens
	return outputAmount / inputAmount // base tokens per community token
}

func keyUserPositionOfToken(ionConnectAddress string) string {
	return fmt.Sprintf("position:%s", ionConnectAddress)
}
