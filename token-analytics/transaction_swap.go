// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

const (
	fatAddressV2Version   = 2      // Fat Address V2 version byte
	fatAddressV2Prefix    = "0x02" // Fat Address V2 hex string prefix
	fatAddressV2MinLength = 32     // 4 (header) + 8 (token header) + 20 (bonding addr) + strings
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
		TotalSupply          string `db:"total_supply"`
	}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(t.type, '') as token_type,
			p.token0 AS pool_token0,
			t.pair_id,
			COALESCE(t.total_supply, '0') as total_supply
		FROM tokens t
		JOIN uniswap_pools p on p.token0 = t.contract_address OR p.token1 = t.contract_address
		WHERE p.pool_address = $1
	`, strings.ToLower(ev.PoolAddress.Hex()))
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
	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, result.ContractAddress, direction, inputAmount, outputAmount, priceUSD, result.TokenExternalAddress, user.UserExternalAddress, result.TokenType, result.TotalSupply, userAddress.Hex()); err != nil {
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
		tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, tx.TransactionHash, result.TokenExternalAddress)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v token %v to notify subscribers", tx.TransactionHash, result.TokenExternalAddress))

			return
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

	const selectClause = `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(t.pair_id, '') as pair_id,
			COALESCE(u.external_address, '') as user_external_address,
			COALESCE(t.type, '') as token_type,
			COALESCE(t.title,'') as title,
			COALESCE(t.ticker,'') as ticker,
			COALESCE(t.image_url, '') as image_url,
			COALESCE(t.price_usd, 0) as price_usd,
			COALESCE(t.total_supply, '0') as total_supply,
			t.platform as platform
		FROM tokens t
		LEFT JOIN users u ON LOWER(u.content_author_id) = LOWER($2)`

	var result *tokenAndUserInfo
	var err error
	var isFirstSwap bool

	hasFatAddress := len(toTokenBytes) > fatAddressV2MinLength && toTokenBytes[0] == fatAddressV2Version

	if hasFatAddress {
		allTokens, _, _, err := extractAllTokensFromFatAddress(toTokenBytes)
		if err != nil {
			return fmt.Errorf("failed to extract tokens from Fat Address: %w", err)
		}
		if len(allTokens) == 0 {
			return fmt.Errorf("no tokens found in Fat Address")
		}
		externalAddress := allTokens[0]
		if externalAddress == "" {
			return fmt.Errorf("external_address is empty in Fat Address")
		}
		result, err = storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB,
			selectClause+` WHERE t.external_address = $1`,
			externalAddress, userAddr)

		if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
			return fmt.Errorf("failed to find token by external_address %v: %w", externalAddress, err)
		}
		if err == nil && strings.EqualFold(result.PairId, ev.Pair.String()) {
			isFirstSwap = true
			log.Debug(fmt.Sprintf("First swap (Fat Address matched): external_address=%s, contract=%s, pair_id=%s",
				externalAddress, result.ContractAddress, ev.Pair.Hex()))
		} else {
			result = nil
		}
	}
	if result == nil {
		result, err = storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB,
			selectClause+` WHERE t.pair_id = $1`,
			ev.Pair.String(), userAddr)
		if err != nil {
			return fmt.Errorf("failed to find token by pair_id %v: %w", ev.Pair.Hex(), err)
		}

		isFirstSwap = false
		log.Debug(fmt.Sprintf("Subsequent/intermediate swap (thin address): token=%s (type=%s), pair_id=%s, user_has_position=%v",
			result.TokenExternalAddress, result.Type, ev.Pair.Hex(), result.UserExternalAddress != ""))
	}

	contractAddress := result.ContractAddress
	actualBaseToken := strings.ToLower(result.BaseToken)

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, baseToken=%s userAddr=%s, isFirstSwap=%v", contractAddress, actualBaseToken, userAddr, isFirstSwap))

	priceInBaseToken := calculatePriceFromSwap(ev.InputAmount, ev.OutputAmount, ev.Direction) // Price: how much ION per 1 community token
	priceUSD, basePriceUSD, err := t.calculatePriceInUSD(ctx, priceInBaseToken, actualBaseToken)
	if err != nil {
		return fmt.Errorf("failed to calculate price in USD for base token %v: %w", actualBaseToken, err)
	}

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddress, ev.Direction, priceUSD, basePriceUSD, userAddr, tx.TransactionHash))

	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, ev.Direction, ev.InputAmount, ev.OutputAmount, priceUSD, result.TokenExternalAddress, result.UserExternalAddress, result.Type, result.TotalSupply, userAddr); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	if err = t.registerTrade(ctx, tx, ev.Direction, ev.InputAmount, ev.OutputAmount, result.ContractAddress, ev.Swapper.Hex(), result.TokenExternalAddress, actualBaseToken, ev.Pair.Bytes()); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v", userAddr)
	}
	if isFirstSwap {
		result.PriceUsd = priceUSD
		if _, err = t.coins.ImportTokenizedCommunitiesCoin(ctx, result); err != nil {
			if !storage.IsErr(err, storage.ErrNotFound) {
				return errors.Wrapf(err, "failed to import tokenized community coin %v %v", result.TokenExternalAddress, result.ContractAddress)
			}
			log.Debug(fmt.Sprintf("Skipping coin import for token %v: external data not found (will be imported later)", result.TokenExternalAddress))
		}
	}
	if result.Type == TokenTypeProfile {
		t.creatorTokenPricesUSD.Store(strings.ToLower(result.ContractAddress), priceUSD)
	}
	tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, tx.TransactionHash, result.TokenExternalAddress)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v token %v to notify subscribers", tx.TransactionHash, result.TokenExternalAddress))

		return nil
	}
	t.subscriptions.NotifySwap(tradeInfo)
	return nil
}

func extractAllTokensFromFatAddress(toTokenBytes []byte) ([]string, common.Address, common.Address, error) {
	if len(toTokenBytes) < 4 {
		return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for V2 header: got %d bytes", len(toTokenBytes))
	}
	version := toTokenBytes[0]
	if version != fatAddressV2Version {
		return nil, common.Address{}, common.Address{}, fmt.Errorf("unsupported fat address version: %d (expected %d)", version, fatAddressV2Version)
	}
	recordsCount := int(toTokenBytes[1])
	presenceMask := uint16(toTokenBytes[2])<<8 | uint16(toTokenBytes[3])
	offset := 4

	externalAddresses := make([]string, 0, recordsCount)

	for i := 0; i < recordsCount; i++ {
		if len(toTokenBytes) < offset+8 {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for token %d header at offset %d", i, offset)
		}

		nameLen := int(toTokenBytes[offset])
		symbolLen := int(toTokenBytes[offset+1])
		extAddrLen := int(toTokenBytes[offset+2])
		tokenMask := uint32(toTokenBytes[offset+4])<<24 | uint32(toTokenBytes[offset+5])<<16 |
			uint32(toTokenBytes[offset+6])<<8 | uint32(toTokenBytes[offset+7])
		offset += 8

		// Skip mandatory bonding address
		if len(toTokenBytes) < offset+20 {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for bonding address at offset %d", offset)
		}
		offset += 20

		// Skip optional bonding prices (64 bytes if bit 0x02 is set)
		if tokenMask&0x02 != 0 {
			if len(toTokenBytes) < offset+64 {
				return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for bonding prices at offset %d", offset)
			}
			offset += 64
		}
		// Skip optional bonding supply (32 bytes if bit 0x04 is set)
		if tokenMask&0x04 != 0 {
			if len(toTokenBytes) < offset+32 {
				return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for bonding supply at offset %d", offset)
			}
			offset += 32
		}

		// Read name, symbol, and external address
		if len(toTokenBytes) < offset+nameLen+symbolLen+extAddrLen {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for token %d (name, symbol, external address) at offset %d", i, offset)
		}
		offset += nameLen + symbolLen
		externalAddress := string(toTokenBytes[offset : offset+extAddrLen])
		offset += extAddrLen

		externalAddresses = append(externalAddresses, externalAddress)
	}

	// Parse optional creator and affiliate addresses
	var creatorAddr, affiliateAddr common.Address
	if presenceMask&0x01 != 0 {
		if len(toTokenBytes) < offset+20 {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for creator address at offset %d", offset)
		}
		creatorAddr = common.BytesToAddress(toTokenBytes[offset : offset+20])
		offset += 20
	}
	if presenceMask&0x02 != 0 {
		if len(toTokenBytes) < offset+20 {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for affiliate address at offset %d", offset)
		}
		affiliateAddr = common.BytesToAddress(toTokenBytes[offset : offset+20])
	}

	return externalAddresses, creatorAddr, affiliateAddr, nil
}

func (t *tokenAnalytics) calculateTokenMarketDataAndUserPosition(ctx context.Context, tx *txEvent, contractAddress string, direction bool, input, output *big.Int, priceUSD float64, tokenExternalAddress, userExternalAddress, tokenType, totalSupply, userBlockchainAddress string) error {
	log.Debug(fmt.Sprintf("Swap processed: contractAddress=%s, tokenExternalAddress=%s, userExternalAddress=%s (will be processed by trigger on tx_logs)",
		contractAddress, tokenExternalAddress, userExternalAddress))

	jobArgs := BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddress,
		UserExternalAddress:   userExternalAddress,
		ContractAddress:       contractAddress,
		TokenExternalAddress:  tokenExternalAddress,
		TransactionHash:       tx.TransactionHash,
	}

	if t.cfg.EnableDummyGenerator {
		var tokenAmount *big.Int
		if !direction { // buy (Direction=false)
			tokenAmount = output // User receives tokens
		} else { // sell (Direction=true)
			tokenAmount = input // User sends tokens
		}

		userPositionKey := keyUserPositionOfToken(tokenExternalAddress)
		currentScore, err := t.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddress).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			log.Error(errors.Wrapf(err, "failed to get current user position for dummy data"))
			currentScore = 0 // Default to 0 if error
		}

		amountFloat := weiToFloat64FromBigInt(tokenAmount)
		var newScore float64
		if !direction { // buy
			newScore = currentScore + amountFloat
		} else { // sell
			newScore = math.Max(0, currentScore-amountFloat)
		}

		newBalanceWei := new(big.Float).Mul(big.NewFloat(newScore), big.NewFloat(1e18))
		newBalanceBigInt, accuracy := newBalanceWei.Int(nil)
		if accuracy != big.Exact {
			log.Warn(fmt.Sprintf("Dummy data: Float to Int conversion lost precision (accuracy=%v) for newScore=%.2f, user=%s", accuracy, newScore, userBlockchainAddress))
		}
		if newBalanceBigInt.Sign() < 0 {
			log.Debug(fmt.Sprintf("Dummy data: NEGATIVE DETECTED! Setting to 0. Was: %s, newScore=%.2f, user=%s", newBalanceBigInt.String(), newScore, userBlockchainAddress))

			newBalanceBigInt = big.NewInt(0)
		}
		balanceStr := newBalanceBigInt.String()
		jobArgs.DummyBalance = &balanceStr

		log.Debug(fmt.Sprintf("Dummy data: Calculated balance=%s (current=%.2f, change=%.2f, new=%.2f) for user=%s, token=%s, direction=%v",
			balanceStr, currentScore, amountFloat, newScore, userBlockchainAddress, tokenExternalAddress, direction))
	}

	if err := t.riverClient.Push(ctx, jobArgs); err != nil {
		return errors.Wrapf(err, "failed to enqueue balance update job for tx %v", tx.TransactionHash)
	}

	totalSupplyBig := new(big.Int)
	totalSupplyBig.SetString(totalSupply, 10)
	totalSupplyFloat := weiToFloat64FromBigInt(totalSupplyBig)
	marketCapUSD := priceUSD * totalSupplyFloat

	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if pErr := pipeliner.ZAdd(ctx, globalTopSetKey, redis.Z{
			Score:  marketCapUSD,
			Member: tokenExternalAddress,
		}).Err(); pErr != nil {
			return pErr
		}
		if tokenType != "" {
			if typeSpecificKey := getTopSetKeyByType(tokenType); typeSpecificKey != "" {
				if pErr := pipeliner.ZAdd(ctx, typeSpecificKey, redis.Z{
					Score:  marketCapUSD,
					Member: tokenExternalAddress,
				}).Err(); pErr != nil {
					return pErr
				}
			}
			if IsContentType(tokenType) {
				if pErr := pipeliner.ZAdd(ctx, globalTopAnyPostSetKey, redis.Z{
					Score:  marketCapUSD,
					Member: tokenExternalAddress,
				}).Err(); pErr != nil {
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
func keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddress string) string {
	return fmt.Sprintf("position_by_user_blockchain_address:%s", tokenExternalAddress)
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
func (t *tokenAndUserInfo) TokenType() string {
	if t.Platform == PlatformGroupXCom {
		return PlatformGroupXCom
	}
	return t.Type
}

func (t *tokenAndUserInfo) PriceUSD() float64 {
	return t.PriceUsd
}

func (t *tokenAnalytics) fetchTradeInfoFromSwap(ctx context.Context, txHash string, tokenExternalAddress string) (*Trade, error) {
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
			
			COALESCE(utp.amount, '0') as balance,
			COALESCE(((utp.amount::NUMERIC / 1e18) * tokens.price_usd), 0) as balance_usd
		FROM token_swaps 
		JOIN tokens ON token_swaps.contract_address = tokens.contract_address
		LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(tokens.content_author_id)
		LEFT JOIN users holder ON LOWER(holder.content_author_id) = LOWER(token_swaps.user_blockchain_address)
		LEFT JOIN user_token_positions utp ON utp.external_address = token_swaps.external_address AND LOWER(utp.user_blockchain_address) = LOWER(token_swaps.user_blockchain_address)
		WHERE token_swaps.transaction_hash = $1 AND token_swaps.external_address = $2
	`
	swap, err := storage.Get[tokenSwap](ctx, t.ingestedDataDB, sql, txHash, tokenExternalAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch trade for tx %v but processed it, is trigger broken?", txHash)
	}
	trades, _ := convertSwapsToTrades([]*tokenSwap{swap})
	if len(trades) == 0 {
		return nil, errors.Errorf("failed to convert swap to trade: %v", swap)
	}

	return trades[0], nil
}
