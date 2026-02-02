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

	"github.com/ice-blockchain/heimdall/accounts"
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
		ContractAddress            string  `db:"contract_address"`
		BaseToken                  string  `db:"base_token"`
		TokenExternalAddress       string  `db:"token_external_address"`
		TokenType                  string  `db:"token_type"`
		Platform                   string  `db:"platform"`
		PoolToken0                 string  `db:"pool_token0"`
		PairId                     string  `db:"pair_id"`
		TotalSupply                string  `db:"total_supply"`
		Burned                     string  `db:"burned"`
		BaseProfileContractAddress *string `db:"base_profile_contract_address"`
		BaseProfileExternalAddress *string `db:"base_profile_external_address"`
	}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT 
			t.contract_address,
			COALESCE(t.base_token, '') as base_token,
			t.external_address as token_external_address,
			COALESCE(t.type, '') as token_type,
			t.platform,
			p.token0 AS pool_token0,
			t.pair_id,
			COALESCE(t.total_supply, '0') as total_supply,
			base_token.contract_address as base_profile_contract_address,
            base_token.external_address as base_profile_external_address,
            COALESCE(burned.amount, '0') as burned
		FROM tokens t
		JOIN uniswap_pools p on p.token0 = t.contract_address OR p.token1 = t.contract_address
		LEFT JOIN tokens base_token ON base_token.contract_address = t.base_token and base_token."type" = 'profile'
		LEFT JOIN fees_transferred burned ON burned.token_external_address = t.external_address AND burned.recipient_bsc_address = $3
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
		FROM user_bsc_addresses uba
		JOIN users u ON u.id = uba.user_id
		WHERE uba.bsc_address = $1
	`, strings.ToLower(userAddress.Hex()))
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
	totalSupplyBig := new(big.Int)
	totalSupplyBig.SetString(result.TotalSupply, 10)
	burnedBig := new(big.Int)
	burnedBig.SetString(result.Burned, 10)
	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, result.ContractAddress, direction, inputAmount, outputAmount, totalSupplyBig, burnedBig, priceUSD, result.TokenExternalAddress, user.UserExternalAddress, result.TokenType, result.Platform, userAddress.Hex(), result.PairId, result.BaseToken, result.BaseProfileContractAddress, result.BaseProfileExternalAddress); err != nil {
		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	pairId := common.HexToHash(result.PairId)
	if err = t.registerTrade(ctx, tx, direction, inputAmount, outputAmount, result.ContractAddress, userAddress.Hex(), result.TokenExternalAddress, strings.ToLower(result.BaseToken), pairId.Bytes(), totalSupplyBig, burnedBig); err != nil {
		return errors.Wrapf(err, "failed to save trade in questdb %v %v tx %v", userAddress, user.UserExternalAddress, tx.TransactionHash)
	}
	if result.TokenType == TokenTypeProfile {
		t.creatorTokenPricesUSD.Store(strings.ToLower(result.ContractAddress), priceUSD)
	}
	go func() {
		tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, tx.TransactionHash, result.ContractAddress, userAddress.Hex())
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v contract %v user %v to notify subscribers", tx.TransactionHash, result.ContractAddress, userAddress.Hex()))

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
			COALESCE(burned.amount, '0') as burned,
			t.platform as platform,
		    base_token.contract_address as base_profile_contract_address,
            base_token.external_address as base_profile_external_address
		FROM tokens t
		LEFT JOIN user_bsc_addresses uba ON uba.bsc_address = $2
		LEFT JOIN users u ON u.id = uba.user_id
		LEFT JOIN tokens base_token ON base_token.contract_address = t.base_token and base_token."type" = 'profile'
		LEFT JOIN fees_transferred burned ON burned.token_external_address = t.external_address AND burned.recipient_bsc_address = $3`

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
		externalAddress := allTokens[0].ExternalAddress
		if externalAddress == "" {
			return fmt.Errorf("external_address is empty in Fat Address")
		}
		result, err = storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB,
			selectClause+` WHERE t.external_address = $1`,
			externalAddress, userAddr, t.cfg.BondingCurve.BurnAddress)

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
			ev.Pair.String(), userAddr, t.cfg.BondingCurve.BurnAddress)
		if err != nil {
			return fmt.Errorf("failed to find token by pair_id %v: %w", ev.Pair.Hex(), err)
		}

		isFirstSwap = false
		log.Debug(fmt.Sprintf("Subsequent/intermediate swap (thin address): token=%s (type=%s), pair_id=%s, user_has_position=%v",
			result.TokenExternalAddress, result.Type, ev.Pair.Hex(), result.UserExternalAddress != ""))
	}

	contractAddress := result.ContractAddress
	actualBaseToken := strings.ToLower(result.BaseToken)

	log.Debug(fmt.Sprintf("onSwap: contractAddress=%s, baseToken=%s userAddr=%s, isFirstSwap=%v, userExternalAddress=%s, tokenExternalAddress=%s",
		contractAddress, actualBaseToken, userAddr, isFirstSwap, result.UserExternalAddress, result.TokenExternalAddress))

	priceInBaseToken := calculatePriceFromSwap(ev.InputAmount, ev.OutputAmount, ev.Direction) // Price: how much ION per 1 community token
	priceUSD, basePriceUSD, err := t.calculatePriceInUSD(ctx, priceInBaseToken, actualBaseToken)
	if err != nil {
		return fmt.Errorf("failed to calculate price in USD for base token %v: %w", actualBaseToken, err)
	}

	log.Debug(fmt.Sprintf("Swap on token %v: direction=%v, price=%v USD (ION price: %v), user=%v, tx:%v",
		contractAddress, ev.Direction, priceUSD, basePriceUSD, userAddr, tx.TransactionHash))
	totalSupplyBig := new(big.Int)
	totalSupplyBig.SetString(result.TotalSupply, 10)
	burnedBig := new(big.Int)
	burnedBig.SetString(result.Burned, 10)
	if err = t.calculateTokenMarketDataAndUserPosition(ctx, tx, contractAddress, ev.Direction, ev.InputAmount, ev.OutputAmount, totalSupplyBig, burnedBig, priceUSD, result.TokenExternalAddress, result.UserExternalAddress, result.Type, result.Platform, userAddr, result.PairId, result.BaseToken, result.BaseProfileContractAddress, result.BaseProfileExternalAddress); err != nil {

		return errors.Wrap(err, "failed to calculate token market data and user position")
	}
	if err = t.registerTrade(ctx, tx, ev.Direction, ev.InputAmount, ev.OutputAmount, result.ContractAddress, ev.Swapper.Hex(), result.TokenExternalAddress, actualBaseToken, ev.Pair.Bytes(), totalSupplyBig, burnedBig); err != nil {
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
	tradeInfo, err := t.fetchTradeInfoFromSwap(ctx, tx.TransactionHash, contractAddress, userAddr)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch trade info for tx %v contract %v user %v to notify subscribers", tx.TransactionHash, contractAddress, userAddr))

		return nil
	}
	t.subscriptions.NotifySwap(tradeInfo)
	return nil
}

func extractAllTokensFromFatAddress(toTokenBytes []byte) ([]*fatAddressToken, common.Address, common.Address, error) {
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

	tokens := make([]*fatAddressToken, 0, recordsCount)
	for i := 0; i < recordsCount; i++ {
		if len(toTokenBytes) < offset+8 {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for token %d header at offset %d", i, offset)
		}

		nameLen := int(toTokenBytes[offset])
		symbolLen := int(toTokenBytes[offset+1])
		extAddrLen := int(toTokenBytes[offset+2])
		tokenTypeByte := toTokenBytes[offset+3]
		tokenMask := uint32(toTokenBytes[offset+4])<<24 | uint32(toTokenBytes[offset+5])<<16 |
			uint32(toTokenBytes[offset+6])<<8 | uint32(toTokenBytes[offset+7])
		offset += 8
		if len(toTokenBytes) < offset+20 {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for bonding address at offset %d", offset)
		}
		priceModelAddress := common.BytesToAddress(toTokenBytes[offset : offset+20])
		priceModel := priceModelAddress.Hex()
		offset += 20
		var startPrice, endPrice *big.Int
		// Skip optional bonding prices (64 bytes if bit 0x02 is set)
		if tokenMask&0x02 != 0 {
			if len(toTokenBytes) < offset+64 {
				return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for bonding prices at offset %d", offset)
			}
			startPrice = new(big.Int)
			startPrice.SetBytes(toTokenBytes[offset : offset+32])
			endPrice = new(big.Int)
			endPrice.SetBytes(toTokenBytes[offset+32 : offset+64])
			offset += 64
		}
		// Skip optional bonding supply (32 bytes if bit 0x04 is set)
		var totalSupply *big.Int
		if tokenMask&0x04 != 0 {
			if len(toTokenBytes) < offset+32 {
				return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for bonding supply at offset %d", offset)
			}
			totalSupply = new(big.Int)
			totalSupply.SetBytes(toTokenBytes[offset : offset+32])
			offset += 32
		}

		// Read name, symbol, and external address
		if len(toTokenBytes) < offset+nameLen+symbolLen+extAddrLen {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("insufficient data for token %d (name, symbol, external address) at offset %d", i, offset)
		}
		name := string(toTokenBytes[offset : offset+nameLen])
		offset += nameLen
		symbol := string(toTokenBytes[offset : offset+symbolLen])
		offset += symbolLen
		externalAddress := string(toTokenBytes[offset : offset+extAddrLen])
		offset += extAddrLen

		tokenType, platform, _, err := parseTokenType(tokenTypeByte, externalAddress)
		if err != nil {
			return nil, common.Address{}, common.Address{}, fmt.Errorf("failed to parse token type for token %d (%v): %w", i, externalAddress, err)
		}
		tokens = append(tokens, &fatAddressToken{
			Symbol:          symbol,
			Name:            name,
			ExternalAddress: externalAddress,
			PricingModel:    priceModel,
			Type:            tokenType,
			Platform:        platform,
			RawType:         tokenTypeByte,
			TotalSupply:     totalSupply,
			StartPrice:      startPrice,
			EndPrice:        endPrice,
		})
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

	return tokens, creatorAddr, affiliateAddr, nil
}

func (t *tokenAnalytics) calculateTokenMarketDataAndUserPosition(ctx context.Context, tx *txEvent, contractAddress string, direction bool, input, output, totalSupply, burned *big.Int,
	priceUSD float64, tokenExternalAddress, userExternalAddress, tokenType, platform, userBlockchainAddress, pairID, baseToken string, baseProfileContractAddress, baseProfileExternalAddress *string) error {
	log.Debug(fmt.Sprintf("Swap processed: contractAddress=%s, tokenExternalAddress=%s, userExternalAddress=%s (will be processed by trigger on tx_logs)",
		contractAddress, tokenExternalAddress, userExternalAddress))

	jobArgs := BalanceUpdateJobArgs{
		UserBlockchainAddress: userBlockchainAddress,
		UserExternalAddress:   userExternalAddress,
		ContractAddress:       contractAddress,
		TokenExternalAddress:  tokenExternalAddress,
		TransactionHash:       tx.TransactionHash,
		PairID:                pairID,
		BaseToken:             baseToken,
		TokenType:             tokenType,
		Platform:              platform,
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

		log.Debug(fmt.Sprintf("Dummy data: Calculated balance=%s (current=%.2f, change=%.2f, new=%.2f) for user=%s (external=%s), token=%s, tx=%s, direction=%v",
			balanceStr, currentScore, amountFloat, newScore, userBlockchainAddress, userExternalAddress, tokenExternalAddress, tx.TransactionHash, direction))
	}

	if err := t.riverClient.Push(ctx, jobArgs); err != nil {
		return errors.Wrapf(err, "failed to enqueue balance update job for tx %v", tx.TransactionHash)
	}
	// base is creator token - user spent some on contentToken, we need to upd position
	if baseProfileContractAddress != nil && baseProfileExternalAddress != nil {
		log.Debug(fmt.Sprintf("Updating user position for base creatorToken: contractAddress=%s, tokenExternalAddress=%s, user=%s tx=%s",
			*baseProfileContractAddress, *baseProfileExternalAddress, userBlockchainAddress, tx.TransactionHash))
		baseJobArgs := BalanceUpdateJobArgs{
			UserBlockchainAddress: userBlockchainAddress,
			UserExternalAddress:   userExternalAddress,
			ContractAddress:       *baseProfileContractAddress,
			TokenExternalAddress:  *baseProfileExternalAddress,
			TransactionHash:       tx.TransactionHash,
			TokenType:             TokenTypeProfile,
			Platform:              platform,
		}
		if err := t.riverClient.Push(ctx, baseJobArgs); err != nil {
			return errors.Wrapf(err, "failed to enqueue balance update job for tx %v (base token %v)", tx.TransactionHash, *baseProfileContractAddress)
		}
	}

	mCap := marketCap(priceUSD, totalSupply, burned)
	marketCapUSD, _ := mCap.Float64()
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if pErr := pipeliner.ZAdd(ctx, globalTopSetKey, redis.Z{
			Score:  marketCapUSD,
			Member: tokenExternalAddress,
		}).Err(); pErr != nil {
			return pErr
		}
		if platform == PlatformGroupXCom {
			if pErr := pipeliner.ZAdd(ctx, globalTopXcomSetKey, redis.Z{
				Score:  marketCapUSD,
				Member: tokenExternalAddress,
			}).Err(); pErr != nil {
				return pErr
			}
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
	case TokenTypeXcom:
		return globalTopXcomSetKey
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
	case TokenTypeXcom:
		return globalTrendingXcomSetKey
	default:
		return ""
	}
}

func getBondingCurveProgressSetKeyByType(tokenType string) string {
	switch tokenType {
	case TokenTypeProfile:
		return globalBondingCurveProgressProfileSetKey
	case TokenTypePost:
		return globalBondingCurveProgressPostSetKey
	case TokenTypeVideo:
		return globalBondingCurveProgressVideoSetKey
	case TokenTypeArticle:
		return globalBondingCurveProgressArticleSetKey
	case TokenTypeAnyPost:
		return globalBondingCurveProgressAnyPostSetKey
	case TokenTypeXcom:
		return globalBondingCurveProgressXcomSetKey
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

func (t *tokenAnalytics) fetchTradeInfoFromSwap(ctx context.Context, txHash string, contractAddress string, userBlockchainAddress string) (*Trade, error) {
	contractAddress = strings.ToLower(contractAddress)
	userBlockchainAddress = strings.ToLower(userBlockchainAddress)
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
		LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = tokens.content_author_id
		LEFT JOIN users creator ON creator.id = creator_addr.user_id
		LEFT JOIN user_bsc_addresses 	holder_addr ON holder_addr.bsc_address = token_swaps.user_blockchain_address
		LEFT JOIN users holder ON holder.id = holder_addr.user_id
		LEFT JOIN user_token_positions utp ON utp.external_address = token_swaps.external_address AND utp.user_blockchain_address = token_swaps.user_blockchain_address
		WHERE token_swaps.transaction_hash = $1 AND token_swaps.contract_address = $2 AND token_swaps.user_blockchain_address = $3
	`
	swap, err := storage.Get[tokenSwap](ctx, t.ingestedDataDB, sql, txHash, contractAddress, userBlockchainAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch trade for tx %v but processed it, is trigger broken?", txHash)
	}
	trades, _ := convertSwapsToTrades([]*tokenSwap{swap})
	if len(trades) == 0 {
		return nil, errors.Errorf("failed to convert swap to trade: %v", swap)
	}

	return trades[0], nil
}

func marketCap(priceInUSD float64, totalSupply, burned *big.Int) *big.Float {
	priceInUsdF := big.NewFloat(priceInUSD)
	totalTokens := big.NewFloat(0).Sub(big.NewFloat(0).SetInt(totalSupply), big.NewFloat(0).SetInt(burned))
	marketCapUSD := big.NewFloat(0).Mul(priceInUsdF, big.NewFloat(0).Quo(totalTokens, big.NewFloat(1e18)))
	return marketCapUSD
}

func (t *tokenAnalyticsUsers) ValidateTransaction(txPayload accounts.TransactionPayload) error {
	if len(txPayload.UserOperations) == 0 {
		return nil // not a tc tx
	}
	hasBondingCurveTx := false
	for _, action := range txPayload.UserOperations {
		if !strings.EqualFold(t.cfg.BondingCurve.SmartContractAddress, action.To) {
			continue
		}
		hasBondingCurveTx = true
		functionSelector := action.Data[:10]
		swapParams, err := bondingcurve.DecodeSwapFunctionParams(functionSelector, action.Data)
		if err != nil {
			if errors.Is(err, bondingcurve.ErrNotFound) {
				return nil // Not swap.
			}
			return errors.Wrapf(err, "failed to parse swap function parameters")
		}
		toTokenParam, ok := swapParams["toToken"]
		if !ok {
			return fmt.Errorf("toToken param not found in swap event")
		}
		toTokenBytes, ok := toTokenParam.([]byte)
		if !ok {
			return fmt.Errorf("toToken is not []byte")
		}
		hasFatAddress := len(toTokenBytes) > fatAddressV2MinLength && toTokenBytes[0] == fatAddressV2Version
		if !hasFatAddress { // call for existing token, blockchain already have info
			continue
		}
		allTokens, _, _, err := extractAllTokensFromFatAddress(toTokenBytes)
		if len(allTokens) == 0 {
			return fmt.Errorf("no tokens found in Fat Address")
		}
		for _, token := range allTokens {
			expectedParams := t.cfg.BondingCurve.CreateTokenDefaults[token.Type]
			if !strings.EqualFold(token.PricingModel, expectedParams.BondingCurveAlgAddress) {
				return errors.Wrapf(ErrValidationFailed, "wrong pricing model for token %s: expected %s, got %s", token.ExternalAddress, expectedParams.BondingCurveAlgAddress, token.PricingModel)
			}
			if token.TotalSupply != nil {
				if token.TotalSupply.String() != expectedParams.EmissionVolume {
					return errors.Wrapf(ErrValidationFailed, "total supply mismatch: expected %s, got %s", expectedParams.EmissionVolume, token.TotalSupply)
				}
			}
			if token.StartPrice != nil {
				if token.StartPrice.String() != expectedParams.InitialPrice {
					return errors.Wrapf(ErrValidationFailed, "start price mismatch: expected %s, got %s", expectedParams.InitialPrice, token.StartPrice)
				}
			}
			if token.EndPrice != nil {
				if token.EndPrice.String() != expectedParams.FinalPrice {
					return errors.Wrapf(ErrValidationFailed, "end price mismatch: expected %s, got %s", expectedParams.FinalPrice, token.EndPrice)
				}
			}
		}
	}
	if hasBondingCurveTx && txPayload.FeeSponsorId != "" {
		if err := t.validateTxGas(txPayload); err != nil {
			return errors.Wrapf(err, "failed to validate fees")
		}
	}
	return nil
}

func (t *tokenAnalyticsUsers) validateTxGas(txPayload accounts.TransactionPayload) error {
	if txPayload.MaxFeePerGas == nil && txPayload.MaxPriorityFeePerGas == nil {
		return nil
	}
	actualFees := t.bscFees.Load()
	slippage := t.cfg.BondingCurve.TransactionValidationFeeSlippage
	expectedMaxFeePerGas, _ := new(big.Int).SetString(actualFees.MaxFeePerGas, 10)
	allowance := new(big.Float).Mul(new(big.Float).SetInt(expectedMaxFeePerGas), big.NewFloat(slippage))
	if txPayload.MaxFeePerGas != nil {
		actualMaxFeePerGas, _ := new(big.Int).SetString(*txPayload.MaxFeePerGas, 10)
		if diff := new(big.Float).Sub(new(big.Float).SetInt(actualMaxFeePerGas), new(big.Float).SetInt(expectedMaxFeePerGas)); diff.Sign() > 0 && diff.Cmp(allowance) > 0 {
			return errors.Wrapf(ErrValidationFailed, "max fee per gas too high: expected %s, got %s", allowance.String(), actualMaxFeePerGas.String())
		}
	}
	expectedMaxPriorityFeePerGas, _ := new(big.Int).SetString(actualFees.MaxPriorityFeePerGas, 10)
	allowance = new(big.Float).Mul(new(big.Float).SetInt(expectedMaxPriorityFeePerGas), big.NewFloat(slippage))
	if txPayload.MaxPriorityFeePerGas != nil {
		actualMaxPriorityFeePerGas, _ := new(big.Int).SetString(*txPayload.MaxPriorityFeePerGas, 10)
		if diff := new(big.Float).Sub(new(big.Float).SetInt(actualMaxPriorityFeePerGas), new(big.Float).SetInt(actualMaxPriorityFeePerGas)); diff.Sign() > 0 && diff.Cmp(allowance) > 0 {
			return errors.Wrapf(ErrValidationFailed, "max priority fee per gas too high: expected %s, got %s", allowance.String(), actualMaxPriorityFeePerGas.String())
		}
	}

	return nil
}
