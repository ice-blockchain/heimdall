// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onSwap(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped) error {
	userAddr := strings.ToLower(ev.Swapper.Hex())

	externalAddress, err := detectExternalAddressFromSwap(ev)
	if err != nil {
		return fmt.Errorf("failed to detect external_address from tx.Input: %w", err)
	}

	type tokenAndUserInfo struct {
		ContractAddress      string `db:"contract_address"`
		BaseToken            string `db:"base_token"`
		TokenExternalAddress string `db:"token_external_address"`
		UserExternalAddress  string `db:"user_external_address"`
		TokenType            string `db:"token_type"`
	}
	result, err := storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB, `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(u.external_address, '') as user_external_address,
			COALESCE(t.type, '') as token_type
		FROM tokens t
		LEFT JOIN users u ON LOWER(u.blockchain_address) = LOWER($2)
		WHERE t.external_address = $1
	`, externalAddress, userAddr)
	if err != nil {
		return fmt.Errorf("failed to find token by external_address %v: %w", externalAddress, err)
	}

	contractAddress := result.ContractAddress
	actualBaseToken := strings.ToLower(result.BaseToken)
	expectedIONAddress := strings.ToLower(t.cfg.IONTokenAddress)

	log.Debug(fmt.Sprintf("onSwap: externalAddress=%s, contractAddress=%s, baseToken=%s", externalAddress, contractAddress, actualBaseToken))

	if actualBaseToken == "" || actualBaseToken != expectedIONAddress {
		return fmt.Errorf("token %v uses invalid base_token %v, expected ION token %v, swap rejected",
			contractAddress, actualBaseToken, expectedIONAddress)
	}

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, userAddr=%s", contractAddress, userAddr))

	ionPriceUSD := t.ionPriceUSD.Load()

	priceInION := calculatePriceFromSwap(ev) // Price: how much ION per 1 community token
	priceUSD := priceInION * (*ionPriceUSD)

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddress, ev.Direction, priceUSD, *ionPriceUSD, userAddr, tx.TransactionHash))

	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, ev, priceUSD, result.TokenExternalAddress, result.UserExternalAddress, result.TokenType); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	if err = t.registerTrade(ctx, tx, ev, externalAddress); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v", userAddr)
	}
	t.subscriptions.NotifySwap(ev)
	return nil
}

func detectExternalAddressFromSwap(ev *bondingcurve.LogTokenSwapped) (string, error) {
	externalAddressParam, ok := ev.Params["toToken"]
	if !ok {
		return "", fmt.Errorf("failed to extract ion_connect_address from tx.Input: toToken param not found")
	}
	externalAddressParamBytes, ok := externalAddressParam.([]byte)
	if !ok {
		return "", fmt.Errorf("failed to extract ion_connect_address from tx.Input: toToken is not bytes")
	}
	externalAddress := string(externalAddressParamBytes)
	return externalAddress, nil
}

func (t *tokenAnalytics) calculateTokenMarketDataAndUserPosition(ctx context.Context, tx *txEvent, contractAddress string, ev *bondingcurve.LogTokenSwapped, priceUSD float64, tokenExternalAddress, userExternalAddress, tokenType string) error {
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

	log.Debug(fmt.Sprintf("Swap processed: contractAddress=%s, tokenExternalAddress=%s, userExternalAddress=%s (will be processed by trigger on tx_logs)",
		contractAddress, tokenExternalAddress, userExternalAddress))

	userPostitionKey := keyUserPositionOfToken(tokenExternalAddress)

	currentScore, err := t.processedDataDB.ZScore(ctx, userPostitionKey, userExternalAddress).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get current user position: %w", err)
	}

	amountFloat := bigIntToFloat(tokenAmount)
	var newScore float64
	if !ev.Direction { // buy
		newScore = currentScore + amountFloat
	} else { // sell
		newScore = currentScore - amountFloat
	}
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if newScore <= 0 {
			if pErr := pipeliner.ZRem(ctx, userPostitionKey, userExternalAddress).Err(); pErr != nil {
				return pErr
			}
		} else {
			if pErr := pipeliner.ZAdd(ctx, userPostitionKey, redis.Z{
				Score:  newScore,
				Member: userExternalAddress,
			}).Err(); pErr != nil {
				return pErr
			}
		}
		if pErr := pipeliner.ZIncrBy(ctx, globalTopSetKey, deltaMarketCapUSD, tokenExternalAddress).Err(); pErr != nil {
			return pErr
		}
		if tokenType != "" {
			if typeSpecificKey := getTopSetKeyByType(tokenType); typeSpecificKey != "" {
				if pErr := pipeliner.ZIncrBy(ctx, typeSpecificKey, deltaMarketCapUSD, tokenExternalAddress).Err(); pErr != nil {
					return pErr
				}
			}
			if IsContentType(tokenExternalAddress) {
				if pErr := pipeliner.ZIncrBy(ctx, globalTopAnyPostSetKey, deltaMarketCapUSD, tokenExternalAddress).Err(); pErr != nil {
					return pErr
				}
			}
		}
		return nil
	}); txErr != nil {
		return fmt.Errorf("failed to update market data for tx %v: %w", tx.TransactionHash, txErr)
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil {
				return fmt.Errorf("failed to `%v` for tx %v: %w", response.FullName(), tx.TransactionHash, rerr)
			}
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

func getTopSetKeyByType(tokenType string) string {
	switch tokenType {
	case TokenTypeProfile:
		return globalTopProfileSetKey
	case TokenTypePost:
		return globalTopPostSetKey
	case TokenTypeVideo:
		return globalTopVideoSetKey
	case TokenTypeArticle:
		return globalTopArticleSetKey
	case TokenTypeAnyPost:
		return globalTopAnyPostSetKey
	default:
		return ""
	}
}

func getTrendingSetKeyByType(tokenType string) string {
	switch tokenType {
	case TokenTypeProfile:
		return globalTrendingProfileSetKey
	case TokenTypePost:
		return globalTrendingPostSetKey
	case TokenTypeVideo:
		return globalTrendingVideoSetKey
	case TokenTypeArticle:
		return globalTrendingArticleSetKey
	case TokenTypeAnyPost:
		return globalTrendingAnyPostSetKey
	default:
		return ""
	}
}
