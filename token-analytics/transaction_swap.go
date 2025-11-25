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

	type tokenAndUserInfo struct {
		ContractAddress string `db:"contract_address"`
		BaseToken       string `db:"base_token"`
		TokenIonConnect string `db:"token_ion_connect"`
		UserIonConnect  string `db:"user_ion_connect"`
	}
	result, err := storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB, `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.ion_connect_address as token_ion_connect,
			COALESCE(u.ion_connect_address, '') as user_ion_connect
		FROM tokens t
		LEFT JOIN users u ON LOWER(u.blockchain_address) = LOWER($2)
		WHERE t.ion_connect_address = $1
	`, ionConnectAddress, userAddr)
	if err != nil {
		return fmt.Errorf("failed to find token by ion_connect_address %v: %w", ionConnectAddress, err)
	}

	contractAddress := result.ContractAddress
	actualBaseToken := strings.ToLower(result.BaseToken)
	expectedIONAddress := strings.ToLower(t.cfg.IONTokenAddress)

	log.Debug(fmt.Sprintf("onSwap: ionConnect=%s, contractAddress=%s, baseToken=%s", ionConnectAddress, contractAddress, actualBaseToken))

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

	return t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, userAddr, ev, priceUSD, result.TokenIonConnect, result.UserIonConnect)
}

func (t *tokenAnalytics) calculateTokenMarketDataAndUserPosition(ctx context.Context, tx *txEvent, contractAddress, userAddr string, ev *bondingcurve.LogTokenSwapped, priceUSD float64, tokenIonConnectAddress, userIonConnectAddress string) error {
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

	log.Debug(fmt.Sprintf("Swap processed: contractAddress=%s, tokenIonConnect=%s, userIonConnect=%s (will be processed by trigger on tx_logs)",
		contractAddress, tokenIonConnectAddress, userIonConnectAddress))

	userPostitionKey := keyUserPositionOfToken(tokenIonConnectAddress)
	if !ev.Direction { // buy (Direction=false)
		if err := t.increaseDragonflyUserPosition(ctx, userPostitionKey, userIonConnectAddress, tokenAmount); err != nil {
			return fmt.Errorf("failed to increase dragonfly balance for %v (user ion_connect: %v): %w", userAddr, userIonConnectAddress, err)
		}
	} else { // sell
		if err := t.decreaseDragonflyUserPosition(ctx, userPostitionKey, userIonConnectAddress, tokenAmount); err != nil {
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

		return fmt.Errorf("failed to save swap data for tx %v: %w", tx.TransactionHash, err)
	}

	return nil
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
