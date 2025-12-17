// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onUniswapSwapped(ctx context.Context, tx *txEvent, ev *bondingcurve.LogUniswapSwapped) error {
	log.Debug(fmt.Sprintf("Uniswap swapped: pool=%s tx=%s", ev.PoolAddress.Hex(), tx.TransactionHash))
	type tokenInfo struct {
		ContractAddress      string `db:"contract_address"`
		BaseToken            string `db:"base_token"`
		TokenExternalAddress string `db:"token_external_address"`
		TokenType            string `db:"token_type"`
		PoolToken0           string `db:"pool_token0"`
		PairId               string `db:"pair_id"`
	}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(t.type, '') as token_type,
			p.token0 AS pool_token0,
			t.pair_id
		FROM tokens t
		JOIN uniswap_pools p on p.token0 = t.contract_address OR p.token1 = t.contract_address
		WHERE p.pool_address = $1
	`, ev.PoolAddress.Hex())
	if err != nil {
		return fmt.Errorf("failed to find token by pool %v: %w", strings.ToLower(ev.PoolAddress.Hex()), err)
	}
	actualBaseToken := strings.ToLower(result.BaseToken)
	expectedIONAddress := strings.ToLower(t.cfg.IONTokenAddress)

	log.Debug(fmt.Sprintf("onUniSwap: externalAddress=%s, contractAddress=%s, baseToken=%s", result.TokenExternalAddress, result.ContractAddress, actualBaseToken))

	if actualBaseToken == "" || actualBaseToken != expectedIONAddress {
		return fmt.Errorf("token %v uses invalid base_token %v, expected ION token %v, swap rejected",
			result.ContractAddress, actualBaseToken, expectedIONAddress)
	}
	var inputAmount, outputAmount *big.Int
	var userAddress common.Address
	var direction bool
	// Detect with token is tc-token (0 or 1, the other one is base), and if pool needs to receive it or send:
	// sent (negative) or must be received (positive)
	if (result.PoolToken0 == result.ContractAddress && ev.Amount0.Sign() > 0) ||
		(result.PoolToken0 != result.ContractAddress && ev.Amount1.Sign() > 0) { // token is sold
		inputAmount = new(big.Int).Abs(ev.Amount0)
		outputAmount = new(big.Int).Abs(ev.Amount1)
		direction = true
	} else {
		inputAmount = new(big.Int).Abs(ev.Amount1)
		outputAmount = new(big.Int).Abs(ev.Amount0)
		direction = false
	}
	if !direction {
		userAddress = ev.Recipient
	} else {
		userAddress = ev.Sender
	}

	type userInfo struct {
		UserExternalAddress string `db:"user_external_address"`
	}
	user, err := storage.Get[userInfo](ctx, t.ingestedDataDB, `
		SELECT 
			COALESCE(u.external_address, '') as user_external_address
		FROM users u
		WHERE LOWER(u.content_author_id) = LOWER($1)
	`, userAddress.Hex())
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to find user by blockchain_address %v: %w", userAddress, err)
	}
	if user == nil {
		user = &userInfo{UserExternalAddress: ""}
	}

	priceInION := calculatePriceFromSwap(inputAmount, outputAmount, direction) // Price: how much ION per 1 community token
	ionPriceUSD := t.ionPriceUSD.Load()
	priceUSD := priceInION * (*ionPriceUSD)

	log.Debug(fmt.Sprintf("Uniswap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		result.ContractAddress, direction, priceUSD, *ionPriceUSD, userAddress, tx.TransactionHash))
	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, result.ContractAddress, direction, inputAmount, outputAmount, priceUSD, result.TokenExternalAddress, user.UserExternalAddress, result.TokenType); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	pairId := common.HexToHash(result.PairId)
	if err = t.registerTrade(ctx, tx, direction, inputAmount, outputAmount, result.ContractAddress, userAddress.Hex(), result.TokenExternalAddress, pairId.Bytes()); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v %v tx %v", userAddress, user.UserExternalAddress, tx.TransactionHash)
	}
	t.subscriptions.NotifySwap(result.TokenExternalAddress)
	return nil
}

func (t *tokenAnalytics) onSwap(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped) error {
	userAddr := strings.ToLower(ev.Swapper.Hex())
	externalAddress, _, err := detectExternalAddressFromSwap(ev)

	isFirstSwap := err == nil && len(externalAddress) > 0
	if isFirstSwap {
		if toTokenParam, ok := ev.Params["toToken"]; ok {
			if toTokenBytes, ok := toTokenParam.([]byte); ok {
				// First swap should have toToken length > 20 (prefix + external_address)
				isFirstSwap = len(toTokenBytes) > 20
			}
		}
	}

	type tokenAndUserInfo struct {
		ContractAddress      string `db:"contract_address"`
		BaseToken            string `db:"base_token"`
		TokenExternalAddress string `db:"token_external_address"`
		UserExternalAddress  string `db:"user_external_address"`
		TokenType            string `db:"token_type"`
	}
	const selectClause = `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(u.external_address, '') as user_external_address,
			COALESCE(t.type, '') as token_type
		FROM tokens t
		LEFT JOIN users u ON LOWER(u.content_author_id) = LOWER($2)`

	var result *tokenAndUserInfo
	if isFirstSwap {
		// First swap: lookup by external_address
		result, err = storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB,
			selectClause+` WHERE t.external_address = $1`,
			externalAddress, userAddr)
		if err != nil {
			return fmt.Errorf("failed to find token by external_address %v: %w", externalAddress, err)
		}
	} else {
		// 1+ swaps: lookup by contract_address
		result, err = storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB,
			selectClause+` WHERE t.pair_id = $1`,
			ev.Pair.String(), userAddr)
		if err != nil {
			return fmt.Errorf("failed to find token by pair_id %v: %w", ev.Pair.Hex(), err)
		}
	}

	contractAddress := result.ContractAddress
	actualBaseToken := strings.ToLower(result.BaseToken)
	expectedIONAddress := strings.ToLower(t.cfg.IONTokenAddress)

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, baseToken=%s", contractAddress, actualBaseToken))

	if actualBaseToken == "" || actualBaseToken != expectedIONAddress {
		return fmt.Errorf("token %v uses invalid base_token %v, expected ION token %v, swap rejected",
			contractAddress, actualBaseToken, expectedIONAddress)
	}

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, userAddr=%s", contractAddress, userAddr))

	ionPriceUSD := t.ionPriceUSD.Load()

	priceInION := calculatePriceFromSwap(ev.InputAmount, ev.OutputAmount, ev.Direction) // Price: how much ION per 1 community token
	priceUSD := priceInION * (*ionPriceUSD)

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddress, ev.Direction, priceUSD, *ionPriceUSD, userAddr, tx.TransactionHash))

	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, ev.Direction, ev.InputAmount, ev.OutputAmount, priceUSD, result.TokenExternalAddress, result.UserExternalAddress, result.TokenType); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	if err = t.registerTrade(ctx, tx, ev.Direction, ev.InputAmount, ev.OutputAmount, result.ContractAddress, ev.Swapper.Hex(), result.TokenExternalAddress, ev.Pair.Bytes()); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v", userAddr)
	}
	t.subscriptions.NotifySwap(result.TokenExternalAddress)
	return nil
}

func detectExternalAddressFromSwap(ev *bondingcurve.LogTokenSwapped) (string, common.Address, error) {
	externalAddressParam, ok := ev.Params["toToken"]
	if !ok {
		return "", common.Address{}, fmt.Errorf("failed to extract ion_connect_address from tx.Input: toToken param not found")
	}
	externalAddressParamBytes, ok := externalAddressParam.([]byte)
	if !ok {
		return "", common.Address{}, fmt.Errorf("failed to extract ion_connect_address from tx.Input: toToken is not bytes")
	}
	var creatorTokenAddr common.Address
	if len(externalAddressParamBytes) > 20 {
		creatorTokenAddr = common.BytesToAddress(externalAddressParamBytes[0:20])
		externalAddressParamBytes = externalAddressParamBytes[20:]
	}
	externalAddress := string(externalAddressParamBytes)
	if len(externalAddress) > 0 {
		externalAddress = externalAddress[1:]
	}
	return externalAddress, creatorTokenAddr, nil
}

func (t *tokenAnalytics) calculateTokenMarketDataAndUserPosition(ctx context.Context, tx *txEvent, contractAddress string, direction bool, input, output *big.Int, priceUSD float64, tokenExternalAddress, userExternalAddress, tokenType string) error {
	var tokenAmount *big.Int
	var sign float64
	if !direction { // buy (Direction=false)
		tokenAmount = output // User receives tokens
		sign = 1.0
	} else { // sell (Direction=true)
		tokenAmount = input // User sends tokens
		sign = -1.0
	}
	deltaMarketCapUSD := sign * weiToFloat64FromBigInt(tokenAmount) * priceUSD

	log.Debug(fmt.Sprintf("Swap processed: contractAddress=%s, tokenExternalAddress=%s, userExternalAddress=%s (will be processed by trigger on tx_logs)",
		contractAddress, tokenExternalAddress, userExternalAddress))

	userPostitionKey := keyUserPositionOfToken(tokenExternalAddress)

	currentScore, err := t.processedDataDB.ZScore(ctx, userPostitionKey, userExternalAddress).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get current user position: %w", err)
	}

	amountFloat := weiToFloat64FromBigInt(tokenAmount)
	var newScore float64
	if !direction { // buy
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
			if IsContentType(tokenType) {
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

func calculatePriceFromSwap(input, output *big.Int, direction bool) float64 {
	inputAmount := weiToFloat64FromBigInt(input)
	outputAmount := weiToFloat64FromBigInt(output)
	if outputAmount == 0 {
		return 0
	}
	if !direction { // buy (Direction=false): user sends base tokens, receives community tokens
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
