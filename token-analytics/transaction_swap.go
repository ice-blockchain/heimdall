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

	log.Debug(fmt.Sprintf("onUniSwap: externalAddress=%s, contractAddress=%s, baseToken=%s", result.TokenExternalAddress, result.ContractAddress, actualBaseToken))

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
		return fmt.Errorf("failed to find user by content author id %v: %w", userAddress, err)
	}
	if user == nil {
		user = &userInfo{UserExternalAddress: ""}
	}

	priceInBaseToken := calculatePriceFromSwap(inputAmount, outputAmount, direction) // Price: how much ION per 1 community token
	priceUSD, basePriceUSD, err := t.calculatePriceInUSD(ctx, priceInBaseToken, actualBaseToken)
	if err != nil {
		return fmt.Errorf("failed to calculate price in USD for base token %v: %w", actualBaseToken, err)
	}

	log.Debug(fmt.Sprintf("Uniswap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		result.ContractAddress, direction, priceUSD, basePriceUSD, userAddress, tx.TransactionHash))
	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, result.ContractAddress, direction, inputAmount, outputAmount, priceUSD, result.TokenExternalAddress, user.UserExternalAddress, result.TokenType); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	pairId := common.HexToHash(result.PairId)
	if err = t.registerTrade(ctx, tx, direction, inputAmount, outputAmount, result.ContractAddress, userAddress.Hex(), result.TokenExternalAddress, strings.ToLower(result.BaseToken), pairId.Bytes()); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v %v tx %v", userAddress, user.UserExternalAddress, tx.TransactionHash)
	}
	if result.TokenType == TokenTypeProfile {
		t.creatorTokenPricesUSD.Store(strings.ToLower(result.ContractAddress), priceUSD)
	}
	go func() {
		tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, tx.TransactionHash)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v token %v to notify subscribers", tx.TransactionHash, result.TokenExternalAddress))
		}
		t.subscriptions.NotifySwap(tradeInfo)
	}()
	return nil
}

func (t *tokenAnalytics) onSwap(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped) error {
	userAddr := strings.ToLower(ev.Swapper.Hex())
	toTokenParam, ok := ev.Params["toToken"]
	if !ok {
		return fmt.Errorf("toToken param not found in swap event")
	}
	toTokenBytes, ok := toTokenParam.([]byte)
	if !ok {
		return fmt.Errorf("toToken is not []byte")
	}
	isFirstSwap := len(toTokenBytes) > 64
	var externalAddress string
	var err error
	if isFirstSwap {
		externalAddress, _, _, err = extractExternalAddressFromToToken(toTokenBytes)
		if err != nil {
			return fmt.Errorf("failed to extract external_address from first swap: %w", err)
		}
		if externalAddress == "" {
			return fmt.Errorf("external_address is empty for first swap")
		}
	}

	const selectClause = `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(u.external_address, '') as user_external_address,
			COALESCE(t.type, '') as token_type,
			COALESCE(t.title,'') as title,
			COALESCE(t.ticker,'') as ticker,
			COALESCE(t.image_url, '') as image_url
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
		log.Debug(fmt.Sprintf("First swap detected: external_address=%s, contract=%s", externalAddress, result.ContractAddress))
	} else {
		// 1+ swaps: lookup by pair_id
		result, err = storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB,
			selectClause+` WHERE t.pair_id = $1`,
			ev.Pair.String(), userAddr)
		if err != nil {
			return fmt.Errorf("failed to find token by pair_id %v: %w", ev.Pair.Hex(), err)
		}
		log.Debug(fmt.Sprintf("Subsequent swap detected: pair_id=%s, contract=%s", ev.Pair.Hex(), result.ContractAddress))
	}

	contractAddress := result.ContractAddress
	actualBaseToken := strings.ToLower(result.BaseToken)

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, baseToken=%s userAddr=%s", contractAddress, actualBaseToken, userAddr))

	priceInBaseToken := calculatePriceFromSwap(ev.InputAmount, ev.OutputAmount, ev.Direction) // Price: how much ION per 1 community token
	priceUSD, basePriceUSD, err := t.calculatePriceInUSD(ctx, priceInBaseToken, actualBaseToken)
	if err != nil {
		return fmt.Errorf("failed to calculate price in USD for base token %v: %w", actualBaseToken, err)
	}

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddress, ev.Direction, priceUSD, basePriceUSD, userAddr, tx.TransactionHash))

	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, ev.Direction, ev.InputAmount, ev.OutputAmount, priceUSD, result.TokenExternalAddress, result.UserExternalAddress, result.TokenType); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	if err = t.registerTrade(ctx, tx, ev.Direction, ev.InputAmount, ev.OutputAmount, result.ContractAddress, ev.Swapper.Hex(), result.TokenExternalAddress, actualBaseToken, ev.Pair.Bytes()); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v", userAddr)
	}
	if isFirstSwap {
		result.PriceUsd = priceUSD
		if _, err = t.coins.ImportTokenizedCommunitiesCoin(ctx, result); err != nil {
			return errors.Wrapf(err, "failed to import tokenized community coin %v %v", result.TokenExternalAddress, result.ContractAddress)
		}

	}
	if result.TokenType == TokenTypeProfile {
		t.creatorTokenPricesUSD.Store(strings.ToLower(result.ContractAddress), priceUSD)
	}
	tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, tx.TransactionHash)
	if err != nil {
		return errors.Wrapf(err, "failed to fetch trade info for tx %v token %v", tx.TransactionHash, result.TokenExternalAddress)
	}
	t.subscriptions.NotifySwap(tradeInfo)
	return nil
}

func extractExternalAddressFromToToken(toTokenBytes []byte) (string, common.Address, common.Address, error) {
	var creatorTokenAddr common.Address
	var affiliateAddr common.Address
	if len(toTokenBytes) > fatAddressHeaderSize {
		creatorTokenAddr = common.BytesToAddress(toTokenBytes[4:24])
		affiliateAddr = common.BytesToAddress(toTokenBytes[24:44])
		symbolLen := int(toTokenBytes[0])
		nameLen := int(toTokenBytes[1])
		if len(toTokenBytes) > fatAddressHeaderSize+symbolLen+nameLen {
			toTokenBytes = toTokenBytes[fatAddressHeaderSize+symbolLen+nameLen:]
		}
	}
	externalAddress := string(toTokenBytes)

	return externalAddress, creatorTokenAddr, affiliateAddr, nil
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

func (t *tokenAnalytics) calculatePriceInUSD(ctx context.Context, priceInBaseToken float64, baseToken string) (price, basePrice float64, err error) {
	if baseToken == "" {
		return 0, 0, errors.New("base token is empty")
	}
	if strings.EqualFold(baseToken, t.cfg.IONTokenAddress) {
		ionPriceUSD := t.ionPriceUSD.Load()
		return priceInBaseToken * (*ionPriceUSD), *ionPriceUSD, nil
	}
	creatorTokenPrice, ok := t.creatorTokenPricesUSD.Load(strings.ToLower(baseToken))
	if !ok {
		basePriceP, err := storage.Get[float64](ctx, t.ingestedDataDB, `SELECT price_usd FROM base_token_prices WHERE token_address = $1`, strings.ToLower(baseToken))
		if err != nil {
			return 0, 0, errors.Wrapf(err, "failed to get price for base token %v", baseToken)
		}
		creatorTokenPrice, _ = t.creatorTokenPricesUSD.LoadOrStore(strings.ToLower(baseToken), *basePriceP)
	}
	return priceInBaseToken * creatorTokenPrice, creatorTokenPrice, nil
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

func (t *tokenAndUserInfo) Address() string {
	return t.ContractAddress
}

func (t *tokenAndUserInfo) Name() string {
	return t.Title
}

func (t *tokenAndUserInfo) Symbol() string {
	return t.Ticker
}

func (t *tokenAndUserInfo) IconUrl() string {
	return t.ImageURL
}
func (t *tokenAndUserInfo) ExternalAddress() string {
	return t.TokenExternalAddress
}

func (t *tokenAndUserInfo) PriceUSD() float64 {
	return t.PriceUsd
}

func (t *tokenAnalytics) fetchTradeInfoFromSwap(ctx context.Context, txHash string) (*Trade, error) {
	sql := `
		SELECT token_swaps.created_at,
		    token_swaps.transaction_hash,
		    token_swaps.contract_address,
		    token_swaps.external_address,
		    tokens.platform,
		    token_swaps.user_blockchain_address,
		    token_swaps.direction,
		    token_swaps.input_amount,
		    token_swaps.output_amount,
		    token_swaps.price_usd,
		    tokens.content_author_id as content_author_id,
			creator.username as creator_username,
			creator.display_name as creator_display,
			creator.verified as creator_verified,
			creator.avatar as creator_avatar,
			creator.external_address as creator_external_address,
			creator.platform_group as creator_platform,
			tokens.content_author_id as creator_bnb_bsc_address,

			holder.master_pubkey as holder_master_pubkey,
			holder.username as holder_username,
			holder.display_name as holder_display,
			holder.verified as holder_verified,
			holder.avatar as holder_avatar,
			holder.external_address as holder_external_address,
			holder.platform_group as holder_platform,
			
			utp.amount as balance,
			COALESCE(((utp.amount::NUMERIC / 1e18) * tokens.price_usd), 0) as balance_usd
		FROM token_swaps 
		JOIN tokens ON token_swaps.contract_address = tokens.contract_address
		LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(tokens.content_author_id)
		LEFT JOIN users holder ON LOWER(holder.content_author_id) = LOWER(token_swaps.user_blockchain_address)
		LEFT JOIN user_token_positions utp ON utp.external_address = token_swaps.external_address AND LOWER(utp.user_blockchain_address) = LOWER(token_swaps.user_blockchain_address)
		WHERE token_swaps.transaction_hash = $1
	`
	swap, err := storage.Get[tokenSwap](ctx, t.ingestedDataDB, sql, txHash)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch trade for tx %v but processed it, is trigger broken?", txHash)
	}
	trades, _ := convertSwapsToTrades([]*tokenSwap{swap})
	if len(trades) == 0 {
		return nil, errors.Errorf("failed to convert swap to trade: %v", swap)
	}

	return trades[0], nil
}
