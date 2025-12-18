// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"
	"github.com/puzpuzpuz/xsync/v4"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

const (
	dummyDataLastBlock = 74298420
	dummyDataStream    = "00000000-0000-0000-0000-000000000000"
)

type (
	dummyDataGenerator struct {
		Target                      *storage.DB
		InsertBlockIndex            uint64
		Stream                      string
		BondingCurveContractAddress string
		IONTokenAddress             string
		MaxTokenGens                uint
		MaxUsers                    uint
		TokenGeneratorTTL           time.Duration
		SavePoint                   *xsync.Map[uint, *SavePoint]
		createdUsers                []string
		userBlockChainToMaster      map[string]string
		usersLock                   sync.RWMutex

		// Per-token user pools for repeated swaps
		tokenUserPools     map[string][]tokenUser
		tokenUserPoolsLock sync.RWMutex

		// Pool of REAL tokens (not dummy) for generating dummy swaps
		realTokenPool     []*tokenRow
		realTokenPoolLock sync.RWMutex
		lastRealTokenSync time.Time

		activeTokensWorkers atomic.Int32
	}
	tokenUser struct {
		blockchainAddress string
		masterPubkey      string
	}
	dummyDataTemplateParams struct {
		Stream                 string
		BlockNumber            uint64
		TxIndex                uint64
		BlockHash              string
		TxHash                 string
		Token                  *tokenRow
		TxData                 string
		TxInput                string
		ContentAuthorID        string
		BondingCurveContract   string
		BondedTokenCreatedData string
		SwappedData            string
		UserBlockchainAddr     string
		BlockTimestamp         uint64
	}
)

func (gen *dummyDataGenerator) Run(ctx context.Context) {
	if gen.MaxTokenGens == 0 {
		gen.MaxTokenGens = 5
	}
	if gen.MaxUsers == 0 {
		gen.MaxUsers = 200_000
	}
	if gen.TokenGeneratorTTL == 0 {
		gen.TokenGeneratorTTL = 4 * time.Hour
	}

	masterPubkey := "9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f"
	err := gen.generateToken(ctx, gen.Stream, &tokenRow{
		ContractAddress: "7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
		ContentAuthorID: &masterPubkey,
		ExternalAddress: string(PlatformIonConnectProfile) + BuildProfileExternalAddress(masterPubkey),
		Title:           "Yu's token",
		Ticker:          "posidoniusenara",
		TotalSupply:     "1000000000000000000000000",
		BaseToken:       "2c73996BaBF1a06c2C057177353293f7cA0907c8",
		PairId:          "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15",
	}, PlatformGroupIonConnect)
	if err != nil {
		if storage.IsErr(err, storage.ErrReadOnly) {
			log.Info("skipping inserting dummy data, DB is read-only")
			return
		}
		log.Panic(errors.Wrapf(err, "failed to insert token data"))
	}

	// Wait for first token to be fully processed by all triggers and workers
	log.Info("Waiting 5 seconds for first token to be processed...")
	time.Sleep(5 * time.Second)

	// Fetch initial pool of real tokens for dummy swap generation
	if err := gen.fetchRealTokens(ctx); err != nil {
		log.Error(errors.Wrap(err, "failed to fetch initial real tokens pool, will retry later"))
	}

	gen.startNewTokenGenerator(ctx, uuid.NewString())
}

func (gen *dummyDataGenerator) createTokenWithBuysOrSellsProcessor(ctx context.Context, stream string, platformGroup string) context.CancelFunc {
	if platformGroup == PlatformGroupXCom {
		return gen.createXComTokenWithBuysOrSellsProcessor(ctx, stream)
	}

	return gen.createIonConnectTokenWithBuysOrSellsProcessor(ctx, stream)
}

func (gen *dummyDataGenerator) createIonConnectTokenWithBuysOrSellsProcessor(ctx context.Context, stream string) context.CancelFunc {
	kinds := []int{0, 30023, 30023, 30175}
	kind := kinds[rand.Intn(len(kinds))]
	dTag := uuid.NewString()

	_, master, err := gen.createUserForPlatform(ctx, mustRandomHex(32), PlatformGroupIonConnect)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to create user for token generation"))
		return nil
	}

	var externalAddress string
	if kind == nostr.KindProfileMetadata {
		dTag = ""
		platformPrefix := string(PlatformIonConnectProfile) // "a"
		externalAddress = platformPrefix + BuildProfileExternalAddress(master)
	} else if kind == nostr.KindArticle {
		platformPrefix := string(PlatformIonConnectArticle) // "d"
		externalAddress = platformPrefix + BuildContentExternalAddress(kind, master, dTag)
	} else if kind == model.CustomIONKindEditableTextNote {
		platformPrefix := string(PlatformIonConnectPost) // "b"
		externalAddress = platformPrefix + BuildContentExternalAddress(kind, master, dTag)
	} else {
		platformPrefix := string(PlatformIonConnectVideo) // "c"
		externalAddress = platformPrefix + BuildContentExternalAddress(kind, master, dTag)
	}
	names := []string{
		"Super Duper Token",
		"Giga token",
		"ToTheMooN",
		"HODL token",
	}
	displayName := names[rand.Int31n(int32(len(names)))]
	symbol := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))
	tok := &tokenRow{
		ContractAddress: generateDummyContractAddress(),
		ContentAuthorID: &master,
		ExternalAddress: externalAddress,
		Title:           displayName,
		Ticker:          symbol,
		TotalSupply:     "1000000000000000000" + strings.Repeat("0", rand.Intn(8)+1),
		BaseToken:       strings.TrimPrefix(gen.IONTokenAddress, "0x"),
		PairId:          "0x" + mustRandomHex(32),
	}
	if err := gen.generateToken(ctx, stream, tok, PlatformGroupIonConnect); err != nil {
		log.Error(errors.Wrapf(err, "failed to insert dummy tx data"))
		return nil
	}

	log.Info(fmt.Sprintf("Started IonConnect token generator for token %v on stream %v by %v", tok.ContractAddress, stream, master))

	deadline := time.Now().Add(gen.TokenGeneratorTTL)
	ctx, cancel := context.WithDeadline(ctx, deadline)

	gen.startBuysOrSellsProcessor(ctx, tok, stream, deadline, PlatformGroupIonConnect)
	gen.startBondingCurveProgressUpdater(ctx, tok, deadline)

	return cancel
}

func (gen *dummyDataGenerator) createXComTokenWithBuysOrSellsProcessor(ctx context.Context, stream string) context.CancelFunc {
	tokenTypes := []struct {
		prefix string
		kind   string
	}{
		{string(PlatformXComProfile), "profile"}, // z
		{string(PlatformXComPost), "post"},       // y
		{string(PlatformXComVideo), "video"},     // x
		{string(PlatformXComArticle), "article"}, // w
	}

	tokenType := tokenTypes[rand.Intn(len(tokenTypes))]

	handle := mustRandomHex(8)
	_, master, err := gen.createUserForPlatform(ctx, handle, PlatformGroupXCom)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to create X.com user for token generation"))

		return nil
	}
	var externalAddress string
	if tokenType.kind == "profile" {
		externalAddress = tokenType.prefix + handle // z{handle}
	} else {
		postID := mustRandomHex(8)
		externalAddress = tokenType.prefix + postID
	}
	names := []string{
		"X Token Pro",
		"Tweet Master",
		"Viral Post",
		"X Infinity",
	}
	displayName := names[rand.Int31n(int32(len(names)))]
	symbol := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))

	tok := &tokenRow{
		ContractAddress: generateDummyContractAddress(),
		ContentAuthorID: &master,
		ExternalAddress: externalAddress,
		Title:           displayName,
		Ticker:          symbol,
		TotalSupply:     "1000000000000000000" + strings.Repeat("0", rand.Intn(8)+1),
		BaseToken:       strings.TrimPrefix(gen.IONTokenAddress, "0x"),
		PairId:          "0x" + mustRandomHex(32),
	}

	if err := gen.generateToken(ctx, stream, tok, PlatformGroupXCom); err != nil {
		log.Error(errors.Wrapf(err, "failed to insert dummy X.com tx data"))
		return nil
	}

	log.Info(fmt.Sprintf("Started X.com token generator for token %v (%v) on stream %v by %v", tok.ContractAddress, tokenType.kind, stream, master))

	deadline := time.Now().Add(gen.TokenGeneratorTTL)
	ctx, cancel := context.WithDeadline(ctx, deadline)

	gen.startBuysOrSellsProcessor(ctx, tok, stream, deadline, PlatformGroupXCom)
	gen.startBondingCurveProgressUpdater(ctx, tok, deadline)

	return cancel
}

func (gen *dummyDataGenerator) fetchRealTokens(ctx context.Context) error {
	sql := `
		SELECT DISTINCT
			t.contract_address,
			t.external_address,
			t.title,
			t.ticker,
			t.total_supply,
			t.base_token,
			t.pair_id,
			t.content_author_id,
			t.created_at
		FROM tokens t
		INNER JOIN transactions tx ON tx.from_address = t.content_author_id
		WHERE tx.to_address = LOWER($1)
		  AND tx.dummy = FALSE
		  AND t.pair_id IS NOT NULL
		  AND t.base_token IS NOT NULL
		ORDER BY t.created_at DESC
		LIMIT 100
	`

	tokens, err := storage.Select[tokenRow](ctx, gen.Target, sql, gen.BondingCurveContractAddress)
	if err != nil {
		return errors.Wrap(err, "failed to fetch real tokens")
	}

	gen.realTokenPoolLock.Lock()
	gen.realTokenPool = tokens
	gen.lastRealTokenSync = time.Now()
	gen.realTokenPoolLock.Unlock()

	log.Info(fmt.Sprintf("Fetched %d real tokens for dummy swap generation", len(tokens)))
	for i, token := range tokens {
		log.Debug(fmt.Sprintf("Real token [%d]: %s (%s)", i, token.ContractAddress, token.Title))
	}
	return nil
}

func (gen *dummyDataGenerator) getRealTokenPool(ctx context.Context) ([]*tokenRow, error) {
	gen.realTokenPoolLock.RLock()
	needsRefresh := time.Since(gen.lastRealTokenSync) > 5*time.Minute
	gen.realTokenPoolLock.RUnlock()

	if needsRefresh {
		if err := gen.fetchRealTokens(ctx); err != nil {
			return nil, err
		}
	}

	gen.realTokenPoolLock.RLock()
	defer gen.realTokenPoolLock.RUnlock()
	return gen.realTokenPool, nil
}

func (gen *dummyDataGenerator) startNewTokenGenerator(ctx context.Context, stream string) {
	ticker := time.NewTicker(60 * time.Second)
	fire := make(chan struct{}, 1)

	go func() {
		defer ticker.Stop()

		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case fire <- struct{}{}:
				default:
					log.Info(fmt.Sprintf("skipping new token generation on stream %v, previous generation still in progress", stream))
				}
			}
		}
	}()

	fire <- struct{}{}
	platformToggle := 0 // 0 for IonConnect, 1 for X.com
	go func() {
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-fire:
				if int(gen.activeTokensWorkers.Load()) >= int(gen.MaxTokenGens) {
					continue
				}
				var platformGroup string
				if platformToggle%2 == 0 {
					platformGroup = PlatformGroupIonConnect
				} else {
					platformGroup = PlatformGroupXCom
				}
				platformToggle++
				gen.createTokenWithBuysOrSellsProcessor(ctx, stream, platformGroup)
			}
		}
	}()

	gen.startDummySwapsForRealTokens(ctx)
}

func (gen *dummyDataGenerator) startDummySwapsForRealTokens(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		defer ticker.Stop()

		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				realTokens, err := gen.getRealTokenPool(ctx)
				if err != nil {
					log.Error(errors.Wrap(err, "failed to get real token pool"))
					continue
				}

				if len(realTokens) == 0 {
					log.Debug("No real tokens available for dummy swap generation")
					continue
				}
				successCount := 0
				for i, token := range realTokens {
					log.Debug(fmt.Sprintf("Processing real token %d/%d: %s (%s)", i+1, len(realTokens), token.ContractAddress, token.Title))

					platformGroup := PlatformGroupIonConnect
					if len(token.ExternalAddress) > 0 {
						prefix := token.ExternalAddress[0]
						if prefix == 'z' || prefix == 'y' || prefix == 'x' || prefix == 'w' {
							platformGroup = PlatformGroupXCom
						}
					}

					// Generate 1-2 dummy swaps for this token (matching dummy token pattern)
					txCount := 1 + rand.Intn(2)
					if err := gen.generateBuyOrSellBatch(ctx, dummyDataStream, token, txCount, platformGroup); err != nil {
						log.Error(errors.Wrapf(err, "failed to generate dummy swaps for real token %s", token.ContractAddress))
					} else {
						successCount++
					}
				}

				if successCount > 0 {
					log.Info(fmt.Sprintf("Generated dummy swaps for %d/%d real tokens", successCount, len(realTokens)))
				}
			}
		}
	}()
}

func calculateTxCountForDeadline(ttl time.Duration, deadline time.Time) (int, time.Duration) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1, time.Minute
	}

	percentage := float64(remaining) / float64(ttl)

	if percentage >= 0.7 {
		return 6, time.Second * 5
	}
	if percentage >= 0.5 {
		return 4, time.Second * 10
	}
	if percentage >= 0.2 {
		return 2, time.Second * 30
	}
	return 1, time.Minute
}

func (gen *dummyDataGenerator) startBondingCurveProgressUpdater(ctx context.Context, tokenData *tokenRow, deadline time.Time) {
	log.Info(fmt.Sprintf("Starting bonding curve updater for token %v", tokenData.ContractAddress))

	_, nextTick := calculateTxCountForDeadline(gen.TokenGeneratorTTL, deadline)
	ticker := time.NewTicker(nextTick)
	fire := make(chan struct{}, 1)

	go func() {
		defer ticker.Stop()

		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, nextTick := calculateTxCountForDeadline(gen.TokenGeneratorTTL, deadline)
				ticker.Reset(nextTick)
				select {
				case fire <- struct{}{}:
				default:
				}
			}
		}
	}()

	fire <- struct{}{}

	go func() {
		goalAmount, _ := new(big.Int).SetString("100000000000000000000000", 10) // 100k tokens in wei
		basePricePerToken := 0.002                                              // $0.002 per token base price

		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				log.Info(fmt.Sprintf("Bonding curve updater for token %v stopped (context done)", tokenData.ContractAddress))
				return
			case <-fire:
				remaining := time.Until(deadline)
				if remaining <= 0 {
					log.Info(fmt.Sprintf("Bonding curve updater for token %v stopped (deadline reached)", tokenData.ContractAddress))
					return
				}

				percentage := float64(remaining) / float64(gen.TokenGeneratorTTL)
				progressPercentage := 1.0 - percentage

				// Add minimum progress to show something immediately
				if progressPercentage < 0.01 {
					progressPercentage = 0.01 // Start at 1% minimum
				}

				// Calculate bonding curve progress
				currentAmount := new(big.Float).Mul(
					new(big.Float).SetInt(goalAmount),
					big.NewFloat(progressPercentage),
				)
				currentAmountInt, _ := currentAmount.Int(nil)

				raisedAmount := new(big.Float).Mul(
					new(big.Float).SetInt(goalAmount),
					big.NewFloat(progressPercentage*0.8), // Raised is 80% of current
				)
				raisedAmountInt, _ := raisedAmount.Int(nil)

				currentAmountTokens := new(big.Float).Quo(
					new(big.Float).SetInt(currentAmountInt),
					big.NewFloat(1e18),
				)
				currentAmountTokensFloat, _ := currentAmountTokens.Float64()
				currentAmountUSD := currentAmountTokensFloat * basePricePerToken

				goalAmountTokens := new(big.Float).Quo(
					new(big.Float).SetInt(goalAmount),
					big.NewFloat(1e18),
				)
				goalAmountTokensFloat, _ := goalAmountTokens.Float64()
				goalAmountUSD := goalAmountTokensFloat * basePricePerToken

				migrated := progressPercentage >= 1.0

				baseLiquidity := 1000.0                                        // $1000 base liquidity
				liquidityUSD := baseLiquidity * (1.0 + progressPercentage*4.0) // Grows 5x

				updateCtx, cancel := context.WithTimeout(ctx, time.Second*5)
				contractAddr := tokenData.ContractAddress
				if !strings.HasPrefix(contractAddr, "0x") {
					contractAddr = "0x" + contractAddr
				}
				rowsAffected, err := storage.Exec(updateCtx, gen.Target, `
					UPDATE tokens
					SET bonding_curve_current_amount = $1,
					    bonding_curve_raised_amount = $2,
					    bonding_curve_goal_amount = $3,
					    bonding_curve_current_amount_usd = $4,
					    bonding_curve_goal_amount_usd = $5,
					    bonding_curve_migrated = $6,
					    liquidity_usd = $7,
					    updated_at = NOW()
					WHERE contract_address = $8
				`, currentAmountInt.String(), raisedAmountInt.String(), goalAmount.String(),
					currentAmountUSD, goalAmountUSD, migrated, liquidityUSD, contractAddr)
				cancel()

				if err != nil {
					log.Error(errors.Wrapf(err, "failed to update bonding curve progress for token %v, stopping updater", tokenData.ContractAddress))
					return
				} else if rowsAffected > 0 {
					log.Info(fmt.Sprintf("✓ SUCCESS: Updated bonding curve for token %v: progress=%.1f%%, liquidity=$%.2f, current=%s, goal=%s",
						tokenData.ContractAddress, progressPercentage*100, liquidityUSD,
						currentAmountInt.String(), goalAmount.String()))
				} else {
					log.Warn(fmt.Sprintf("✗ FAIL: Bonding curve update for token %v affected 0 rows - token NOT FOUND in DB, stopping updater", tokenData.ContractAddress))
					return
				}
			}
		}
	}()
}

func (gen *dummyDataGenerator) getOrCreateTokenUserPool(ctx context.Context, tokenContractAddress string, platformGroup string) ([]tokenUser, error) {
	gen.tokenUserPoolsLock.RLock()
	if pool, exists := gen.tokenUserPools[tokenContractAddress]; exists && len(pool) > 0 {
		gen.tokenUserPoolsLock.RUnlock()
		return pool, nil
	}
	gen.tokenUserPoolsLock.RUnlock()

	gen.tokenUserPoolsLock.Lock()
	defer gen.tokenUserPoolsLock.Unlock()

	if pool, exists := gen.tokenUserPools[tokenContractAddress]; exists && len(pool) > 0 {
		return pool, nil
	}
	poolSize := 10 + rand.Intn(11)
	pool := make([]tokenUser, 0, poolSize)

	for i := 0; i < poolSize; i++ {
		var userMasterPubkey string
		if platformGroup == PlatformGroupXCom {
			userMasterPubkey = mustRandomHex(8)
		} else {
			userMasterPubkey = mustRandomHex(32)
		}

		userBlockChainAddr, master, err := gen.createUserForPlatform(ctx, userMasterPubkey, platformGroup)
		if err != nil {
			return nil, err
		}

		pool = append(pool, tokenUser{
			blockchainAddress: userBlockChainAddr,
			masterPubkey:      master,
		})
	}

	if gen.tokenUserPools == nil {
		gen.tokenUserPools = make(map[string][]tokenUser)
	}
	gen.tokenUserPools[tokenContractAddress] = pool

	log.Info(fmt.Sprintf("Created user pool of %d users for token %s", len(pool), tokenContractAddress))

	return pool, nil
}

func (gen *dummyDataGenerator) startBuysOrSellsProcessor(ctx context.Context, tokenData *tokenRow, stream string, deadline time.Time, platformGroup string) {
	txCount, nextTick := calculateTxCountForDeadline(gen.TokenGeneratorTTL, deadline)
	ticker := time.NewTicker(nextTick)
	fire := make(chan int, 1)

	gen.activeTokensWorkers.Add(1)

	go func() {
		defer ticker.Stop()

		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				txCount, nextTick = calculateTxCountForDeadline(gen.TokenGeneratorTTL, deadline)
				ticker.Reset(nextTick)
				select {
				case fire <- txCount:
				default:
					log.Info(fmt.Sprintf("skipping new buy/sell generation on stream %v for token %v, previous generation still in progress", stream, tokenData.ContractAddress))
				}
			}
		}
	}()

	fire <- txCount

	go func() {
		defer gen.activeTokensWorkers.Add(-1)

		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case txCount := <-fire:
				insCtx, insCancel := context.WithTimeout(ctx, time.Second*10)
				if err := gen.generateBuyOrSellBatch(insCtx, stream, tokenData, txCount, platformGroup); err != nil {
					log.Error(errors.Wrapf(err, "failed to insert dummy tx data"))
				}
				insCancel()
			}
		}
	}()
}

func (gen *dummyDataGenerator) generateBuyOrSellBatch(ctx context.Context, stream string, token *tokenRow, totalTx int, platformGroup string) error {
	isRealToken := !strings.Contains(token.ContractAddress, "deadbeef")

	// Use special stream_id for dummy swaps on real tokens
	if isRealToken {
		stream = "00000000-0000-0000-0000-000000000000"
	}

	userPool, err := gen.getOrCreateTokenUserPool(ctx, token.ContractAddress, platformGroup)
	if err != nil {
		return errors.Wrapf(err, "failed to get user pool for token %s", token.ContractAddress)
	}

	blockNum := atomic.AddUint64(&gen.InsertBlockIndex, 1)
	baseTimestamp := time.Now().In(time.UTC).Unix()
	txsForBlock := []string{}
	for txIdx := range totalTx {
		user := userPool[rand.Intn(len(userPool))]
		userBlockChainAddr := user.blockchainAddress
		buyOrSel := rand.Intn(2) == 0
		// Each tx in batch gets unique timestamp (1 second apart)
		txTimestamp := uint64(baseTimestamp + int64(txIdx))

		minTokens := 100.0   // minimum 100 tokens
		maxTokens := 10000.0 // maximum 10000 tokens
		tokensToTrade := minTokens + rand.Float64()*(maxTokens-minTokens)

		// Price range: 100-1000 ION per token (realistic prices like $0.2 - $2 per token)
		minPriceIon := 100.0  // 100 ION per token = $0.2 per token at ION=$0.002
		maxPriceIon := 1000.0 // 1000 ION per token = $2 per token at ION=$0.002
		pricePerTokenIon := minPriceIon + rand.Float64()*(maxPriceIon-minPriceIon)

		tokenAmountWei := new(big.Float).Mul(big.NewFloat(tokensToTrade), big.NewFloat(1e18))
		tokenAmount, _ := tokenAmountWei.Int(nil) // Amount of tokens in wei

		ionAmountFloat := new(big.Float).Mul(big.NewFloat(tokensToTrade), big.NewFloat(pricePerTokenIon))
		ionAmountWei := new(big.Float).Mul(ionAmountFloat, big.NewFloat(1e18))
		ionAmount, _ := ionAmountWei.Int(nil) // Amount of ION in wei
		var inputAmount, outputAmount *big.Int
		if buyOrSel { // SELL
			inputAmount = tokenAmount // selling tokens
			outputAmount = ionAmount  // receiving ION
		} else { // BUY
			inputAmount = ionAmount    // paying ION
			outputAmount = tokenAmount // receiving tokens
		}

		data, packErr := bondingcurve.ABI.Events["Swapped"].Inputs.NonIndexed().Pack(
			buyOrSel,
			inputAmount,
			outputAmount,
			new(big.Int).SetInt64(0),
		)
		if packErr != nil {
			return packErr
		}
		baseTokenBytes, _ := hex.DecodeString(strings.TrimPrefix(token.BaseToken, "0x"))
		// For 1+ swaps, use contract_address directly (not external_address in bytes)
		contractAddr, _ := hex.DecodeString(strings.TrimPrefix(token.ContractAddress, "0x"))

		var baseToken, toToken []byte
		if buyOrSel {
			// SELL: baseToken = contract address, toToken = ION
			baseToken = make([]byte, 20)
			copy(baseToken, contractAddr)
			toToken = make([]byte, 20)
			copy(toToken, baseTokenBytes)
		} else {
			// BUY: baseToken = ION, toToken = contract address
			baseToken = make([]byte, 20)
			copy(baseToken, baseTokenBytes)
			toToken = make([]byte, 20)
			copy(toToken, contractAddr)
		}

		txInput, packErr := bondingcurve.ABI.Methods["swap"].Inputs.Pack(
			baseToken,
			toToken,
			inputAmount,
			outputAmount,
			bondingcurve.BondingCurvePermitData{ // ERC-2612, just values for serializer to pass
				Value:    new(big.Int).SetInt64(0),
				Deadline: new(big.Int).SetInt64(0),
				V:        0,
				R:        [32]byte{},
				S:        [32]byte{},
			},
		)
		if packErr != nil {
			return packErr
		}
		tmpl, tmplErr := template.New("swap_tx").Parse(`{
      "accessList": [],
      "blockHash": "0x{{.BlockHash}}",
      "blockNumber": "{{.BlockNumber}}",
      "blockTimestamp": "{{.BlockTimestamp}}",
      "chainId": "0x61",
      "from": "0x{{.UserBlockchainAddr}}",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "0x{{.TxHash}}",
      "input": "0x83362e17{{.TxInput}}",
      "logs": [{
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x{{.SwappedData}}",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0",
            "0x000000000000000000000000{{.UserBlockchainAddr}}",
            "{{.Token.PairId}}"
          ]
        },
       {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x2",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000dc4fd80a011b2ffec23a6e35ab6d0918f5972f3"
          ]
        }
		],
      "maxFeePerGas": "0x4a817c800",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "nonce": "0x6",
      "r": "0xcf368ec13b2f7dfaad0bde4aac890ff51636111bb8220dfdd904aeb975f5bc0f",
      "s": "0x229edc4496b34d243ac4980aa17955dd6928bf8f6077f386934249782b695545",
      "to": "0x{{.Token.ContractAddress}}",
      "transactionIndex": "{{.TxIndex}}",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
	}`)
		if tmplErr != nil {
			return errors.Wrapf(tmplErr, "failed to insert dummy contract data: malformed template")
		}
		buf := bytes.NewBuffer([]byte{})
		bondingCurveNoPrefix := strings.TrimPrefix(gen.BondingCurveContractAddress, "0x")
		execErr := tmpl.Execute(buf, &dummyDataTemplateParams{
			Stream:               stream,
			BlockNumber:          blockNum,
			BlockTimestamp:       txTimestamp,
			TxIndex:              uint64(txIdx + 1),
			BlockHash:            mustRandomHex(32),
			TxHash:               mustRandomHex(32),
			Token:                token,
			UserBlockchainAddr:   userBlockChainAddr,
			TxInput:              hex.EncodeToString(txInput),
			BondingCurveContract: bondingCurveNoPrefix,
			SwappedData:          hex.EncodeToString(data),
		})
		if execErr != nil {
			return errors.Wrapf(execErr, "failed to insert dummy contract data: malformed template")
		}

		txsForBlock = append(txsForBlock, buf.String())
	}
	fullData := fmt.Sprintf(`{"stream": "%[1]v", "transactions": [`+strings.Join(txsForBlock, ",")+`]}`, stream)
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err = storage.Exec(ctx, gen.Target, sql, blockNum, stream, fullData)
	return errors.Wrapf(err, "failed to insert dummy tx data")
}

func (gen *dummyDataGenerator) generateToken(ctx context.Context, stream string, seedData *tokenRow, platformGroup string) error {
	blockNum := atomic.AddUint64(&gen.InsertBlockIndex, 1)
	txHash := mustRandomHex(32)
	blockHash := mustRandomHex(32)
	ownerBlockchainAddr, _, err := gen.createUserForPlatform(ctx, strVal(seedData.ContentAuthorID), platformGroup)
	if err != nil {
		return errors.Wrapf(err, "failed to create user for token generation")
	}
	base, _ := hex.DecodeString(strings.TrimPrefix(gen.IONTokenAddress, "0x"))
	totalSupply, _ := new(big.Int).SetString(seedData.TotalSupply, 10)

	// For first swap: toToken = 64 zero bytes (see fat address in contact) + external_address (as string bytes)
	typ := seedData.ExternalAddress[0]
	toToken := append(make([]byte, 64+len(seedData.Ticker)+len(seedData.Title)), []byte(seedData.ExternalAddress[1:])...)
	toToken[0] = byte(len(seedData.Ticker))
	toToken[1] = byte(len(seedData.Title))
	toToken[2] = byte(len(seedData.ExternalAddress[1:]))
	toToken[3] = byte(typ)
	copy(toToken[4:], common.HexToAddress(ownerBlockchainAddr).Bytes()) // creatorAddress
	copy(toToken[24:], common.HexToAddress("0x").Bytes())               // affiliateAddress
	copy(toToken[44:], common.HexToAddress("0x").Bytes())               // creatorTokenAddress
	copy(toToken[64:], seedData.Ticker)
	copy(toToken[64+len(seedData.Ticker):], seedData.Title)
	txInput, err := bondingcurve.ABI.Methods["swap"].Inputs.Pack(
		base,
		toToken,
		totalSupply,
		totalSupply,
		bondingcurve.BondingCurvePermitData{ // ERC-2612, just values for serializer to pass
			Value:    new(big.Int).SetInt64(0),
			Deadline: new(big.Int).SetInt64(0),
			V:        0,
			R:        [32]byte{},
			S:        [32]byte{},
		},
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack token created tx input")
	}
	bondedTokenCreatedData, err := bondingcurve.ABI.Events["BondingTokenCreated"].Inputs.NonIndexed().Pack(
		seedData.Title,
		seedData.Ticker,
		common.HexToAddress("0x"),   // creatorTokenAddress for content tokens
		seedData.ExternalAddress[0], // externalType
		seedData.ExternalAddress[1:],
		common.HexToAddress(ownerBlockchainAddr), // creatorAddress
		common.HexToAddress("0x"),                // affilate address
		totalSupply,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack BondingTokenCreated")
	}
	tmpl, err := template.New("token").Parse(`{
  "stream": "{{.Stream}}",
  "transactions": [
    {
      "accessList": [],
      "blockHash": "0x1c818b62bab665dc5227957887d03d354ed2d8ea2048d126610d8b78d389a4a8",
      "blockNumber": "{{.BlockNumber}}",
      "blockTimestamp": "{{.BlockTimestamp}}",
      "chainId": "0x61",
      "from": "0x{{.ContentAuthorID}}",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "0x{{.TxHash}}",
      "input": "{{.TxInput}}",
      "logs": [
        {
	  "address": "0x{{.Token.ContractAddress}}",
          "data": "0x",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0x{{.BondingCurveContract}}",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x2",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x00000000000000000000000000000000000000000000d3c21bcecceda1000000",
          "logIndex": "0x3",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "{{.BondedTokenCreatedData}}",
          "logIndex": "0x4",
          "removed": false,
          "topics": [
            "0xf1aad4192131f14ec094f5319421d9274539312c962d0ce8121ba86f52f25db0",
            "0x000000000000000000000000{{.Token.ContractAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2",
          "logIndex": "0x5",
          "removed": false,
          "topics": [
            "0xc391f1439e6a5d64454067a61cc30295e026850c66d0dcb87e5c74c455862408",
            "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x",
          "logIndex": "0x6",
          "removed": false,
          "topics": [
            "0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4",
            "{{.Token.PairId}}",
            "0x000000000000000000000000{{.Token.BaseToken}}",
            "0x000000000000000000000000{{.Token.ContractAddress}}"
          ]
        },
        {
          "address": "0x2c73996babf1a06c2c057177353293f7ca0907c8",
          "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0x7",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x000000000000000000000000c6646173c7f997949494dfd87d2076ea41b801fb",
            "0x000000000000000000000000{{.BondingCurveContract}}"
          ]
        },
        {
          "address": "0x{{.Token.ContractAddress}}",
          "data": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0x8",
          "removed": false,
          "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x0000000000000000000000008d86c992ce7812a64101da9b2531d5f378d682e2",
            "0x000000000000000000000000{{.ContentAuthorID}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000",
          "logIndex": "0x9",
          "removed": false,
          "topics": [
            "0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0",
            "0x000000000000000000000000{{.ContentAuthorID}}",
            "{{.Token.PairId}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x0000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "logIndex": "0xa",
          "removed": false,
          "topics": [
            "0x65184e4e64eca5b9cd1401ff3001ac8803c660b9ac3bf7af10b7fae4b146b446",
            "{{.Token.PairId}}"
          ]
        }
      ],
      "maxFeePerGas": "0x4a817c800",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "nonce": "0x6",
      "r": "0xcf368ec13b2f7dfaad0bde4aac890ff51636111bb8220dfdd904aeb975f5bc0f",
      "s": "0x229edc4496b34d243ac4980aa17955dd6928bf8f6077f386934249782b695545",
      "to": "0x8d86c992ce7812a64101da9b2531d5f378d682e2",
      "transactionIndex": "0x1",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
    }
  ]
}`)
	if err != nil {
		return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
	}
	buf := bytes.NewBuffer([]byte{})
	bondingCurveNoPrefix := strings.TrimPrefix(gen.BondingCurveContractAddress, "0x")
	err = tmpl.Execute(buf, &dummyDataTemplateParams{
		Stream:                 stream,
		BlockNumber:            blockNum,
		BlockTimestamp:         uint64(time.Now().In(time.UTC).Unix()),
		TxIndex:                1,
		BlockHash:              blockHash,
		TxHash:                 txHash,
		Token:                  seedData,
		TxInput:                "0x83362e17" + hex.EncodeToString(txInput),
		ContentAuthorID:        ownerBlockchainAddr,
		BondingCurveContract:   bondingCurveNoPrefix,
		BondedTokenCreatedData: "0x" + hex.EncodeToString(bondedTokenCreatedData),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
	}
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err = storage.Exec(ctx, gen.Target, sql, blockNum, stream, buf.String())
	return errors.Wrapf(err, "failed to insert dummy contract data")
}

func mustRandomHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		log.Panic(errors.Wrapf(err, "failed to generate random"))
	}
	return hex.EncodeToString(bytes)
}

func generateDummyContractAddress() string {
	var buf bytes.Buffer

	buf.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0})

	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		log.Panic(errors.Wrapf(err, "failed to generate random"))
	}
	buf.Write(suffix)

	return hex.EncodeToString(buf.Bytes())
}
func (gen *dummyDataGenerator) createUserForPlatform(ctx context.Context, masterPubkey string, platformGroup string) (blockchainAddress string, master string, err error) {
	gen.usersLock.Lock()
	defer gen.usersLock.Unlock()

	// Check if user with this masterPubkey already exists
	for existingAddr, existingMaster := range gen.userBlockChainToMaster {
		if existingMaster == masterPubkey {
			log.Info(fmt.Sprintf("User with masterPubkey %v already exists, reusing blockchain address 0x%v", masterPubkey, existingAddr))
			return existingAddr, masterPubkey, nil
		}
	}

	if len(gen.createdUsers) >= int(gen.MaxUsers) {
		userIdx := rand.Intn(len(gen.createdUsers))
		blockchainAddress = gen.createdUsers[userIdx]
		return blockchainAddress, gen.userBlockChainToMaster[blockchainAddress], nil
	}

	blockchainAddress = mustRandomHex(20)

	id := "us-0x" + blockchainAddress
	names := []string{
		"Diwata Lea",
		"Bohuslav Ferdinand",
		"Bethuel Gilbert",
		"Posidonius Enara",
		"Edwena İldar",
	}
	idx := rand.Int31n(int32(len(names)))
	displayName := names[idx]
	usernameBase := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))
	username := usernameBase + mustRandomHex(4)
	verified := rand.Intn(2) == 0
	lookup := strings.ToLower(strings.TrimSpace(username + " " + displayName))
	ionConnectRelays := []string{"wss://141.95.59.70:4443", "wss://181.41.142.217:4443", "wss://94.100.16.233:4443"}
	avatarURLs := []string{
		"https://api.dicebear.com/7.x/avataaars/svg?seed=" + username,
		"https://api.dicebear.com/7.x/lorelei/svg?seed=" + username,
		"https://api.dicebear.com/7.x/personas/svg?seed=" + username,
		"https://api.dicebear.com/7.x/bottts/svg?seed=" + username,
		"https://api.dicebear.com/7.x/identicon/svg?seed=" + username,
		"https://ui-avatars.com/api/?name=" + username + "&background=random&size=300",
	}
	avatarURL := avatarURLs[rand.Intn(len(avatarURLs))]

	var externalAddress string
	if platformGroup == PlatformGroupXCom {
		externalAddress = masterPubkey // Twitter userId
	} else {
		externalAddress = BuildProfileExternalAddress(masterPubkey)
	}

	_, err = storage.Exec(ctx, gen.Target, `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, content_author_id, external_address, username, 
			display_name, avatar, lookup, ion_connect_relays, verified, platform_group
		) VALUES (
			NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
		ON CONFLICT (content_author_id) 
		DO UPDATE SET
			updated_at = NOW(),
			id = EXCLUDED.id,
			master_pubkey = EXCLUDED.master_pubkey,
			external_address = EXCLUDED.external_address,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			avatar = EXCLUDED.avatar,
			lookup = EXCLUDED.lookup,
			ion_connect_relays = EXCLUDED.ion_connect_relays,
			verified = EXCLUDED.verified,
			platform_group = EXCLUDED.platform_group
	`, id, masterPubkey, "0x"+blockchainAddress, externalAddress, username, displayName, avatarURL, lookup, ionConnectRelays, verified, platformGroup)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			log.Info(fmt.Sprintf("User %v already exists (duplicate OK), using blockchain address 0x%v", masterPubkey, blockchainAddress))
		} else {
			return "", "", fmt.Errorf("failed to upsert user %v: %w", masterPubkey, err)
		}
	}

	log.Info(fmt.Sprintf("Created dummy user %v: %v with blockchain address 0x%v for platform %v", username, masterPubkey, blockchainAddress, platformGroup))

	gen.createdUsers = append(gen.createdUsers, blockchainAddress)
	if gen.userBlockChainToMaster == nil {
		gen.userBlockChainToMaster = make(map[string]string)
	}
	gen.userBlockChainToMaster[blockchainAddress] = masterPubkey

	return blockchainAddress, masterPubkey, nil
}

func boolPtr(b bool) *bool {
	return &b
}
