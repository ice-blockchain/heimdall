// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
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
		TokenFactoryContractAddress string
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
		TokenFactoryContract   string
		BondedTokenCreatedData string
		PairRegisteredData     string
		SwappedData            string
		UserBlockchainAddr     string
		BlockTimestamp         uint64
		EntryPointAddr         string
		IONTokenAddress        string
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

	// Ensure BNB price exists in database for dummy mode (use price ~$600)
	_, err := storage.Exec(ctx, gen.Target, `
		INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
		VALUES ('BNB', 'BNB', 600.0, NOW())
		ON CONFLICT (token_address) DO UPDATE SET
			price_usd = EXCLUDED.price_usd,
			updated_at = EXCLUDED.updated_at
	`)
	if err != nil {
		log.Error(errors.Wrap(err, "failed to insert dummy BNB price"))
	}

	// Ensure ION price exists in database for dummy mode (use price ~$0.01)
	_, err = storage.Exec(ctx, gen.Target, `
		INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
		VALUES ($1, 'ION', 0.01, NOW())
		ON CONFLICT (token_address) DO UPDATE SET
			price_usd = EXCLUDED.price_usd,
			updated_at = EXCLUDED.updated_at
	`, strings.ToLower(gen.IONTokenAddress))
	if err != nil {
		log.Error(errors.Wrap(err, "failed to insert dummy ION price"))
	}

	masterPubkey := "9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f"
	err = gen.generateToken(ctx, gen.Stream, &tokenRow{
		ContractAddress: "7307ea7ab4a7e5bcba1bf18c9495d08107d9f0d8",
		ContentAuthorID: &masterPubkey,
		ExternalAddress: BuildProfileExternalAddress(masterPubkey),
		Type:            "profile",
		Title:           "Yu's token",
		Ticker:          "posidoniusenara",
		TotalSupply:     "1000000000000000000000000",
		BaseToken:       "2c73996BaBF1a06c2C057177353293f7cA0907c8",
		PairId:          "0xc481c7a805798bc81ca4cbf0803d38bd785357f2ab3b22b70e42dedc13046e15",
	}, PlatformGroupIonConnect, 'a') // 'a' for IonConnect Profile
	if err != nil {
		if storage.IsErr(err, storage.ErrReadOnly) {
			log.Info("skipping inserting dummy data, DB is read-only")
			return
		}
		log.Panic(errors.Wrapf(err, "failed to insert token data"))
	}

	log.Info("Waiting 5 seconds for first token to be processed...")
	time.Sleep(5 * time.Second)

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
	kind := kinds[cryptoRandInt(len(kinds))]
	dTag := uuid.NewString()

	_, master, err := gen.createUserForPlatform(ctx, mustRandomHex(32), PlatformGroupIonConnect)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to create user for token generation"))
		return nil
	}

	var externalAddress string
	var tokenType string
	var externalType uint8
	if kind == nostr.KindProfileMetadata {
		dTag = ""
		externalAddress = BuildProfileExternalAddress(master)
		tokenType = "profile"
		externalType = 'a' // IonConnect Profile
	} else if kind == nostr.KindArticle {
		externalAddress = BuildContentExternalAddress(kind, master, dTag)
		tokenType = "article"
		externalType = 'd' // IonConnect Article
	} else if kind == model.CustomIONKindEditableTextNote {
		externalAddress = BuildContentExternalAddress(kind, master, dTag)
		tokenType = "post"
		externalType = 'b' // IonConnect Post
	} else {
		externalAddress = BuildContentExternalAddress(kind, master, dTag)
		tokenType = "post"
		externalType = 'b' // IonConnect Post
	}
	names := []string{
		"Super Duper Token",
		"Giga token",
		"ToTheMooN",
		"HODL token",
	}
	displayName := names[cryptoRandInt(len(names))]
	symbol := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))
	tok := &tokenRow{
		ContractAddress: generateDummyContractAddress(),
		ContentAuthorID: &master,
		ExternalAddress: externalAddress,
		Type:            tokenType,
		Title:           displayName,
		Ticker:          symbol,
		TotalSupply:     "1000000000000000000" + strings.Repeat("0", cryptoRandInt(8)+1),
		BaseToken:       strings.ToLower(strings.TrimPrefix(gen.IONTokenAddress, "0x")),
		PairId:          "0x" + mustRandomHex(32),
	}
	if err := gen.generateToken(ctx, stream, tok, PlatformGroupIonConnect, externalType); err != nil {
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

	tokenType := tokenTypes[cryptoRandInt(len(tokenTypes))]

	handle := mustRandomHex(8)
	_, master, err := gen.createUserForPlatform(ctx, handle, PlatformGroupXCom)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to create X.com user for token generation"))

		return nil
	}
	names := []string{
		"X Token Pro",
		"Tweet Master",
		"Viral Post",
		"X Infinity",
	}
	displayName := names[cryptoRandInt(len(names))]
	symbol := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))

	tok := &tokenRow{
		ContractAddress: generateDummyContractAddress(),
		ContentAuthorID: &master,
		ExternalAddress: handle,
		Type:            tokenType.kind,
		Title:           displayName,
		Ticker:          symbol,
		TotalSupply:     "1000000000000000000" + strings.Repeat("0", cryptoRandInt(8)+1),
		BaseToken:       strings.ToLower(strings.TrimPrefix(gen.IONTokenAddress, "0x")),
		PairId:          "0x" + mustRandomHex(32),
	}
	externalTypeByte := uint8(tokenType.prefix[0])

	if err := gen.generateToken(ctx, stream, tok, PlatformGroupXCom, externalTypeByte); err != nil {
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

// Double swap transaction: ION → Creator Token → Content Token
func (gen *dummyDataGenerator) createDoubleSwapTokenGenerator(ctx context.Context, stream string) context.CancelFunc {
	_, master, err := gen.createUserForPlatform(ctx, mustRandomHex(32), PlatformGroupIonConnect)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to create user for double swap token generation"))
		return nil
	}

	// Creator Token (Profile)
	creatorExternalAddress := BuildProfileExternalAddress(master)
	creatorToken := &tokenRow{
		ContractAddress: generateDummyContractAddress(),
		ContentAuthorID: &master,
		ExternalAddress: creatorExternalAddress,
		Title:           "Creator Profile",
		Ticker:          "CREA",
		TotalSupply:     "1000000000000000000000000",
		BaseToken:       strings.ToLower(strings.TrimPrefix(gen.IONTokenAddress, "0x")),
		PairId:          "0x" + mustRandomHex(32),
	}

	// Content Token (Post)
	kind := model.CustomIONKindEditableTextNote
	dTag := uuid.NewString()
	contentExternalAddress := BuildContentExternalAddress(kind, master, dTag)
	contentToken := &tokenRow{
		ContractAddress: generateDummyContractAddress(),
		ContentAuthorID: &master,
		ExternalAddress: contentExternalAddress,
		Title:           "Content Post",
		Ticker:          "CONT",
		TotalSupply:     "980000000000000000000000", // slightly less due to fee on first swap
		BaseToken:       creatorToken.ContractAddress,
		PairId:          "0x" + mustRandomHex(32),
	}

	blockNum := atomic.AddUint64(&gen.InsertBlockIndex, 1)
	txHash := mustRandomHex(32)
	blockHash := mustRandomHex(32)
	ownerBlockchainAddr, _, err := gen.createUserForPlatform(ctx, *creatorToken.ContentAuthorID, PlatformGroupIonConnect)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to create user for double swap"))
		return nil
	}

	base, _ := hex.DecodeString(strings.TrimPrefix(gen.IONTokenAddress, "0x"))
	totalSupply, _ := new(big.Int).SetString(creatorToken.TotalSupply, 10)

	creatorExtType := uint8('a')
	creatorExtAddr := creatorExternalAddress
	contentExtType := uint8('b')
	contentExtAddr := contentExternalAddress

	toToken := buildFatAddressV2Double(
		creatorToken.Title, creatorToken.Ticker, creatorExtAddr, creatorExtType,
		contentToken.Title, contentToken.Ticker, contentExtAddr, contentExtType,
		common.HexToAddress(ownerBlockchainAddr),
		common.HexToAddress("0x"),
	)

	// Use 4-param swap method (swap0 in ABI, method ID 0x83362e17) for double swap
	txInput, err := bondingcurve.ABI.Pack("swap0",
		base,
		toToken,
		totalSupply,
		totalSupply,
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack double swap tx input"))

		return nil
	}

	creatorTokenCreatedData, err := bondingcurve.ABI.Events["BondingTokenCreated"].Inputs.NonIndexed().Pack(
		creatorToken.Title,
		creatorToken.Ticker,
		creatorExtType,
		creatorExtAddr,
		totalSupply,
		common.HexToAddress(ownerBlockchainAddr),
		common.HexToAddress("0x"),
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack creator BondingTokenCreated"))

		return nil
	}

	// Pack SECOND BondingTokenCreated event (Content Token)
	contentTotalSupply, _ := new(big.Int).SetString(contentToken.TotalSupply, 10)
	contentTokenCreatedData, err := bondingcurve.ABI.Events["BondingTokenCreated"].Inputs.NonIndexed().Pack(
		contentToken.Title,
		contentToken.Ticker,
		contentExtType,
		contentExtAddr,
		contentTotalSupply,
		common.HexToAddress(ownerBlockchainAddr),
		common.HexToAddress("0x"),
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack content BondingTokenCreated"))

		return nil
	}

	// Pack FIRST Swapped event (ION → Creator)
	firstSwappedData, err := bondingcurve.ABI.Events["Swapped"].Inputs.NonIndexed().Pack(
		false, // direction: buy
		common.HexToAddress(strings.ToLower(gen.IONTokenAddress)), // feeToken (ION)
		totalSupply,   // inputAmount
		totalSupply,   // outputAmount (1:1 at bonding curve start)
		big.NewInt(0), // fee
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack first Swapped event"))

		return nil
	}

	// Pack SECOND Swapped event (Creator → Content)
	secondSwappedData, err := bondingcurve.ABI.Events["Swapped"].Inputs.NonIndexed().Pack(
		false, // direction: buy
		common.HexToAddress(creatorToken.ContractAddress), // feeToken (Creator Token)
		totalSupply,        // inputAmount (all creator tokens)
		contentTotalSupply, // outputAmount (slightly less due to fee)
		big.NewInt(0),      // fee
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack second Swapped event"))

		return nil
	}

	// Pack FIRST PairRegistered event (ION ↔ Creator)
	startPrice := big.NewInt(1e18) // 1
	endPrice := big.NewInt(1e18)   // 1
	firstPairRegisteredData, err := bondingcurve.ABI.Events["PairRegistered"].Inputs.NonIndexed().Pack(
		common.HexToAddress("0xdead"), // priceModel
		startPrice,
		endPrice,
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack first PairRegistered event"))

		return nil
	}

	// Pack SECOND PairRegistered event (Creator ↔ Content)
	secondPairRegisteredData, err := bondingcurve.ABI.Events["PairRegistered"].Inputs.NonIndexed().Pack(
		common.HexToAddress("0xdead"), // priceModel
		startPrice,
		endPrice,
	)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to pack second PairRegistered event"))
		return nil
	}

	// 2x BondingTokenCreated, 2x PairRegistered, 2x Swapped
	tmpl, err := template.New("doubleSwap").Parse(`{
  "stream": "{{.Stream}}",
  "transactions": [
    {
      "accessList": [],
      "blockHash": "0x{{.BlockHash}}",
      "blockNumber": "{{.BlockNumber}}",
      "blockTimestamp": "{{.BlockTimestamp}}",
      "chainId": "0x61",
      "from": "0x{{.UserBlockchainAddr}}",
      "gas": "0x2dc6c0",
      "gasPrice": "0x3b9aca00",
      "hash": "0x{{.TxHash}}",
      "input": "{{.TxInput}}",
      "logs": [
        {
          "address": "0x{{.TokenFactoryContract}}",
          "data": "{{.CreatorTokenCreatedData}}",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd",
            "0x000000000000000000000000{{.CreatorToken.ContractAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "{{.FirstPairRegisteredData}}",
          "logIndex": "0x2",
          "removed": false,
          "topics": [
            "0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c",
            "{{.CreatorToken.PairId}}",
            "0x000000000000000000000000{{.CreatorToken.BaseToken}}",
            "0x000000000000000000000000{{.CreatorToken.ContractAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "{{.FirstSwappedData}}",
          "logIndex": "0x3",
          "removed": false,
          "topics": [
            "0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81",
            "0x000000000000000000000000{{.UserBlockchainAddr}}",
            "{{.CreatorToken.PairId}}"
          ]
        },
        {
          "address": "0x{{.TokenFactoryContract}}",
          "data": "{{.ContentTokenCreatedData}}",
          "logIndex": "0x4",
          "removed": false,
          "topics": [
            "0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd",
            "0x000000000000000000000000{{.ContentToken.ContractAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "{{.SecondPairRegisteredData}}",
          "logIndex": "0x5",
          "removed": false,
          "topics": [
            "0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c",
            "{{.ContentToken.PairId}}",
            "0x000000000000000000000000{{.ContentToken.BaseToken}}",
            "0x000000000000000000000000{{.ContentToken.ContractAddress}}"
          ]
        },
        {
          "address": "0x{{.BondingCurveContract}}",
          "data": "{{.SecondSwappedData}}",
          "logIndex": "0x6",
          "removed": false,
          "topics": [
            "0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81",
            "0x000000000000000000000000{{.UserBlockchainAddr}}",
            "{{.ContentToken.PairId}}"
          ]
        }
      ],
      "maxFeePerGas": "0x3b9aca00",
      "maxPriorityFeePerGas": "0x3b9aca00",
      "nonce": "0x1",
      "r": "0x1",
      "s": "0x1",
      "to": "0x{{.BondingCurveContract}}",
      "transactionIndex": "0x1",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
    }
  ]
}`)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to parse double swap template"))

		return nil
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{
		"Stream":                   stream,
		"BlockNumber":              blockNum,
		"BlockHash":                blockHash,
		"TxHash":                   txHash,
		"TxInput":                  "0x" + hex.EncodeToString(txInput),
		"UserBlockchainAddr":       strings.TrimPrefix(ownerBlockchainAddr, "0x"),
		"BondingCurveContract":     strings.TrimPrefix(gen.BondingCurveContractAddress, "0x"),
		"TokenFactoryContract":     strings.TrimPrefix(gen.TokenFactoryContractAddress, "0x"),
		"CreatorToken":             creatorToken,
		"ContentToken":             contentToken,
		"CreatorTokenCreatedData":  "0x" + hex.EncodeToString(creatorTokenCreatedData),
		"ContentTokenCreatedData":  "0x" + hex.EncodeToString(contentTokenCreatedData),
		"FirstPairRegisteredData":  "0x" + hex.EncodeToString(firstPairRegisteredData),
		"SecondPairRegisteredData": "0x" + hex.EncodeToString(secondPairRegisteredData),
		"FirstSwappedData":         "0x" + hex.EncodeToString(firstSwappedData),
		"SecondSwappedData":        "0x" + hex.EncodeToString(secondSwappedData),
		"BlockTimestamp":           uint64(time.Now().Unix()),
	}); err != nil {
		log.Error(errors.Wrapf(err, "failed to execute double swap template"))
		return nil
	}

	fullData := buf.String()
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)
			ON CONFLICT (from_block_number, to_block_number, network) DO NOTHING`
	if _, err = storage.Exec(ctx, gen.Target, sql, blockNum, stream, fullData); err != nil && !storage.IsErr(err, storage.ErrDuplicate) {
		log.Error(errors.Wrapf(err, "failed to insert double swap tx data"))
		return nil
	}

	log.Info(fmt.Sprintf("Created DOUBLE SWAP: ION → %v (creator) → %v (content) on stream %v by %v",
		creatorToken.ContractAddress, contentToken.ContractAddress, stream, master))

	// Wait for SQL triggers to process the double swap transaction before starting subsequent swaps
	// This prevents race condition where startBuysOrSellsProcessor generates swaps for tokens that don't exist yet
	time.Sleep(2 * time.Second)

	deadline := time.Now().Add(gen.TokenGeneratorTTL)
	ctx1, cancel1 := context.WithDeadline(ctx, deadline)
	ctx2, cancel2 := context.WithDeadline(ctx, deadline)

	gen.startBuysOrSellsProcessor(ctx1, creatorToken, stream, deadline, PlatformGroupIonConnect)
	gen.startBondingCurveProgressUpdater(ctx1, creatorToken, deadline)

	gen.startBuysOrSellsProcessor(ctx2, contentToken, stream, deadline, PlatformGroupIonConnect)
	gen.startBondingCurveProgressUpdater(ctx2, contentToken, deadline)

	return func() {
		cancel1()
		cancel2()
	}
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
	tokenCounter := 0 // Counter for token generation: every 3rd token is double swap
	go func() {
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-fire:
				if int(gen.activeTokensWorkers.Load()) >= int(gen.MaxTokenGens) {
					continue
				}

				// Every 2nd token: create double swap (profile + content)
				if tokenCounter%2 == 1 {
					gen.createDoubleSwapTokenGenerator(ctx, stream)
				} else {
					var platformGroup string
					if tokenCounter%2 == 0 {
						platformGroup = PlatformGroupIonConnect
					} else {
						platformGroup = PlatformGroupXCom
					}
					gen.createTokenWithBuysOrSellsProcessor(ctx, stream, platformGroup)
				}
				tokenCounter++
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
					txCount := 1 + cryptoRandInt(2)
					if err := gen.generateBuyOrSellBatch(ctx, dummyDataStream, token, txCount, platformGroup); err != nil {
						log.Error(errors.Wrapf(err, "failed to generate dummy swaps for real token %s", token.ContractAddress))
					} else {
						successCount++
					}

					// 30% chance to also generate P2P transfers for this token
					if cryptoRandInt(10) < 3 {
						transferCount := 1 + cryptoRandInt(2) // 1-2 P2P transfers
						if err := gen.generateP2PTransferBatch(ctx, dummyDataStream, token, transferCount, platformGroup); err != nil {
							log.Error(errors.Wrapf(err, "failed to generate P2P transfers for real token %s", token.ContractAddress))
						}
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
	poolSize := 10 + cryptoRandInt(11)
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

				// 30% chance to also generate P2P transfers for this token
				if cryptoRandInt(10) < 3 {
					transferCount := 1 + cryptoRandInt(3) // 1-3 P2P transfers
					if err := gen.generateP2PTransferBatch(insCtx, stream, tokenData, transferCount, platformGroup); err != nil {
						log.Error(errors.Wrapf(err, "failed to generate P2P transfer tx"))
					}
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
	baseTimestamp := time.Now().In(time.UTC).Add(-30 * time.Second).Unix()
	txsForBlock := []string{}
	for txIdx := range totalTx {
		user := userPool[cryptoRandInt(len(userPool))]
		userBlockChainAddr := user.blockchainAddress
		buyOrSel := cryptoRandInt(2) == 0
		// Each tx in batch gets unique timestamp (1 second apart)
		txTimestamp := uint64(baseTimestamp + int64(txIdx))

		// 50% chance to generate custom handleOps transaction
		useCustomHandleOps := cryptoRandInt(2) == 0

		minTokens := 100.0   // minimum 100 tokens
		maxTokens := 10000.0 // maximum 10000 tokens
		tokensToTrade := minTokens + cryptoRandFloat64()*(maxTokens-minTokens)

		// Price range: 100-1000 ION per token (realistic prices like $0.2 - $2 per token)
		minPriceIon := 100.0  // 100 ION per token = $0.2 per token at ION=$0.002
		maxPriceIon := 1000.0 // 1000 ION per token = $2 per token at ION=$0.002
		pricePerTokenIon := minPriceIon + cryptoRandFloat64()*(maxPriceIon-minPriceIon)

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

		feeTokenAddress := common.HexToAddress(strings.TrimPrefix(token.BaseToken, "0x"))
		data, packErr := bondingcurve.ABI.Events["Swapped"].Inputs.NonIndexed().Pack(
			buyOrSel,
			feeTokenAddress,
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

		swapCalldata, packErr := bondingcurve.ABI.Methods["swap"].Inputs.Pack(
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

		var txInput string
		var entryPointAddr string

		if useCustomHandleOps {
			// Custom handleOps: send to smart account (user's address)
			entryPointAddr = userBlockChainAddr
			// Generate custom handleOps transaction
			// handleOps(bytes userOps, uint256 r, uint256 vs)
			//
			// Structure according to specification:
			// [1.1]: 0x74fa4121 (selector)
			// [1.2]: offset to userOps (0x60 = 96 bytes)
			// [1.3]: r (32 bytes signature)
			// [1.4]: vs (32 bytes signature, EIP-2098 compact)
			// [1.5]: userOps length (32 bytes)
			// [2.1]: sender (20 bytes, NOT 32!)
			// [2.2]: nonce (32 bytes)
			// [2.3]: callDataLength (32 bytes)
			// [2.4]: callData (variable, contains swap() call)

			swapSelector := "83362e17" // swap 4-param selector
			innerCallData := swapSelector + hex.EncodeToString(swapCalldata)

			// [2.1] Sender: 20 bytes (NOT padded to 32!)
			senderBytes, _ := hex.DecodeString(userBlockChainAddr)
			if len(senderBytes) != 20 {
				return errors.New("invalid sender address length")
			}

			// [2.2] Nonce: 32 bytes
			nonceInt, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(^uint64(0)))
			nonce := fmt.Sprintf("%064x", nonceInt.Uint64())

			// [2.3] CallData length: 32 bytes (length in bytes)
			callDataLengthBytes := len(innerCallData) / 2
			callDataLength := fmt.Sprintf("%064x", callDataLengthBytes)

			// [2.4] CallData: variable length (the actual swap() call)
			callData := innerCallData

			// Build userOps bytes: sender(20) + nonce(32) + callDataLength(32) + callData(variable)
			userOpsData := userBlockChainAddr + nonce + callDataLength + callData

			// [1.5] UserOps length in bytes
			userOpsLengthBytes := len(userOpsData) / 2
			userOpsLength := fmt.Sprintf("%064x", userOpsLengthBytes)

			// [1.3] r: 32 bytes (random signature part 1)
			r := mustRandomHex(32)

			// [1.4] vs: 32 bytes (random signature part 2, EIP-2098 compact)
			vs := mustRandomHex(32)

			// [1.2] Offset to userOps: always 0x60 (96 bytes = selector(4) + offset(32) + r(32) + vs(32))
			userOpsOffset := fmt.Sprintf("%064x", 96)

			// [1.1] Selector: 0x74fa4121
			handleOpsSelector := "74fa4121"

			// Assemble: selector + offset + r + vs + length + data
			txInput = handleOpsSelector +
				userOpsOffset +
				r +
				vs +
				userOpsLength +
				userOpsData
		} else {
			// Direct swap transaction
			txInput = hex.EncodeToString(swapCalldata)
		}

		var tmplStr string
		if useCustomHandleOps {
			// Custom handleOps transaction template (to EntryPoint contract)
			tmplStr = `{
      "accessList": [],
      "blockHash": "0x{{.BlockHash}}",
      "blockNumber": "{{.BlockNumber}}",
      "blockTimestamp": "{{.BlockTimestamp}}",
      "chainId": "0x61",
      "from": "0x{{.UserBlockchainAddr}}",
      "gas": "0x14af2d",
      "gasPrice": "0x3b9aca00",
      "hash": "0x{{.TxHash}}",
      "input": "0x{{.TxInput}}",
      "logs": [{
          "address": "0x{{.BondingCurveContract}}",
          "data": "0x{{.SwappedData}}",
          "logIndex": "0x1",
          "removed": false,
          "topics": [
            "0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81",
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
      "to": "0x{{.EntryPointAddr}}",
      "transactionIndex": "{{.TxIndex}}",
      "type": "0x2",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
	}`
		} else {
			// Direct swap transaction template
			tmplStr = `{
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
            "0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81",
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
	}`
		}
		tmpl, tmplErr := template.New("swap_tx").Parse(tmplStr)
		if tmplErr != nil {
			return errors.Wrapf(tmplErr, "failed to insert dummy contract data: malformed template")
		}
		buf := bytes.NewBuffer([]byte{})
		bondingCurveNoPrefix := strings.TrimPrefix(gen.BondingCurveContractAddress, "0x")

		templateParams := &dummyDataTemplateParams{
			Stream:               stream,
			BlockNumber:          blockNum,
			BlockTimestamp:       txTimestamp,
			TxIndex:              uint64(txIdx + 1),
			BlockHash:            mustRandomHex(32),
			TxHash:               mustRandomHex(32),
			Token:                token,
			UserBlockchainAddr:   userBlockChainAddr,
			TxInput:              txInput,
			BondingCurveContract: bondingCurveNoPrefix,
			SwappedData:          hex.EncodeToString(data),
			IONTokenAddress:      strings.ToLower(gen.IONTokenAddress),
		}

		if useCustomHandleOps {
			templateParams.EntryPointAddr = entryPointAddr
		}

		execErr := tmpl.Execute(buf, templateParams)
		if execErr != nil {
			return errors.Wrapf(execErr, "failed to insert dummy contract data: malformed template")
		}

		txsForBlock = append(txsForBlock, buf.String())

		txType := "direct"
		if useCustomHandleOps {
			txType = "custom handleOps"
		}
		log.Debug(fmt.Sprintf("Generated %s swap tx for token %s: buy=%v, amount=%s",
			txType, token.ContractAddress, !buyOrSel, inputAmount.String()))
	}
	fullData := fmt.Sprintf(`{"stream": "%[1]v", "transactions": [`+strings.Join(txsForBlock, ",")+`]}`, stream)
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)
			ON CONFLICT (from_block_number, to_block_number, network) DO NOTHING`
	_, err = storage.Exec(ctx, gen.Target, sql, blockNum, stream, fullData)
	if err != nil && !storage.IsErr(err, storage.ErrDuplicate) {
		return errors.Wrapf(err, "failed to insert dummy tx data")
	}
	return nil
}

// buildFatAddressV2 — общий энкодер для 1-2 записей.
// Флаги — inline (0x01/0x02/0x04), порядок и размеры как в спецификации v2.
func buildFatAddressV2(tokens []*fatAddressToken, creatorAddr, affiliateAddr common.Address) ([]byte, error) {
	if len(tokens) == 0 {
		return nil, errors.New("FatAddress v2 of zero length")
	}

	// --- Global Header (4 bytes): [version][recordsCount][presenceMask uint16 BE]
	presenceMask := uint16(0)
	if creatorAddr != (common.Address{}) {
		presenceMask |= 0x01
	}
	if affiliateAddr != (common.Address{}) {
		presenceMask |= 0x02
	}

	result := make([]byte, 0, 256)
	result = append(result,
		2, // version
		byte(len(tokens)),
		byte(presenceMask>>8),
		byte(presenceMask),
	)

	// --- Per-token records ---
	for _, t := range tokens {
		nameBytes := []byte(t.Name)
		symbolBytes := []byte(t.Symbol)
		extAddrBytes := []byte(t.ExternalAddress)

		if len(nameBytes) > 255 || len(symbolBytes) > 255 || len(extAddrBytes) > 255 {
			return nil, errors.New("name/symbol/externalAddress length must fit in uint8")
		}

		tokenMask := uint32(0)

		if t.StartPrice != nil && t.EndPrice != nil {
			tokenMask |= 0x02
		}
		if t.TotalSupply != nil {
			tokenMask |= 0x04
		}

		// Token Header (8 bytes): [nameLen][symLen][extAddrLen][extType][tokenMask uint32 BE]
		result = append(result,
			byte(len(nameBytes)),
			byte(len(symbolBytes)),
			byte(len(extAddrBytes)),
			byte(t.Type[0]),
			byte(tokenMask>>24),
			byte(tokenMask>>16),
			byte(tokenMask>>8),
			byte(tokenMask),
		)

		// Bonding Address (20 bytes, mandatory even if zeroed)
		result = append(result, common.HexToAddress(t.PricingModel).Bytes()...)

		// Optional prices: 2 * uint256 (64 bytes)
		if tokenMask&0x02 != 0 {
			begin32, err := uint256ToBytes32(t.StartPrice)
			if err != nil {
				return nil, err
			}
			end32, err := uint256ToBytes32(t.EndPrice)
			if err != nil {
				return nil, err
			}
			result = append(result, begin32...)
			result = append(result, end32...)
		}

		// Optional supply: 1 * uint256 (32 bytes)
		if tokenMask&0x04 != 0 {
			supply32, err := uint256ToBytes32(t.TotalSupply)
			if err != nil {
				return nil, err
			}
			result = append(result, supply32...)
		}

		// Variable strings
		result = append(result, nameBytes...)
		result = append(result, symbolBytes...)
		result = append(result, extAddrBytes...)
	}

	// --- Global addresses (at the end) ---
	if presenceMask&0x01 != 0 {
		result = append(result, creatorAddr.Bytes()...)
	}
	if presenceMask&0x02 != 0 {
		result = append(result, affiliateAddr.Bytes()...)
	}

	return result, nil
}

func uint256ToBytes32(v *big.Int) ([]byte, error) {
	if v == nil {
		return nil, errors.New("uint256 value is nil")
	}
	if v.Sign() < 0 {
		return nil, errors.New("uint256 must be non-negative")
	}
	if v.BitLen() > 256 {
		return nil, errors.New("uint256 overflows 256 bits")
	}
	out := make([]byte, 32)
	be := v.Bytes()
	copy(out[32-len(be):], be)
	return out, nil
}

func buildFatAddressV2Single(name, symbol, externalAddress string, externalType byte, creatorAddr, affiliateAddr common.Address) []byte {
	b, err := buildFatAddressV2([]*fatAddressToken{
		{
			Name:            name,
			Symbol:          symbol,
			ExternalAddress: externalAddress,
			Type:            string([]byte{externalType}),
		},
	}, creatorAddr, affiliateAddr)
	if err != nil {
		panic(err)
	}
	return b
}

func buildFatAddressV2Double(
	name1, symbol1, externalAddress1 string, externalType1 byte,
	name2, symbol2, externalAddress2 string, externalType2 byte,
	creatorAddr, affiliateAddr common.Address,
) []byte {
	b, err := buildFatAddressV2([]*fatAddressToken{
		{
			Name:            name1,
			Symbol:          symbol1,
			ExternalAddress: externalAddress1,
			Type:            string([]byte{externalType1}),
		},
		{
			Name:            name2,
			Symbol:          symbol2,
			ExternalAddress: externalAddress2,
			Type:            string([]byte{externalType2}),
		},
	}, creatorAddr, affiliateAddr)
	if err != nil {
		panic(err)
	}
	return b
}

func (gen *dummyDataGenerator) generateToken(ctx context.Context, stream string, seedData *tokenRow, platformGroup string, externalType uint8) error {
	blockNum := atomic.AddUint64(&gen.InsertBlockIndex, 1)
	txHash := mustRandomHex(32)
	blockHash := mustRandomHex(32)
	ownerBlockchainAddr, _, err := gen.createUserForPlatform(ctx, strVal(seedData.ContentAuthorID), platformGroup)
	if err != nil {
		return errors.Wrapf(err, "failed to create user for token generation")
	}
	base, _ := hex.DecodeString(strings.TrimPrefix(gen.IONTokenAddress, "0x"))
	totalSupply, _ := new(big.Int).SetString(seedData.TotalSupply, 10)

	toToken := buildFatAddressV2Single(
		seedData.Title,
		seedData.Ticker,
		seedData.ExternalAddress,
		externalType,
		common.HexToAddress(ownerBlockchainAddr),
		common.HexToAddress("0x"),
	)
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
		externalType,
		seedData.ExternalAddress,
		totalSupply,
		common.HexToAddress(ownerBlockchainAddr), // creatorAddress
		common.HexToAddress("0x"),                // affiliate address
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack BondingTokenCreated")
	}

	// Pack Swapped event for first swap (ION → Token)
	swappedData, err := bondingcurve.ABI.Events["Swapped"].Inputs.NonIndexed().Pack(
		false, // direction: buy
		common.HexToAddress(strings.ToLower(gen.IONTokenAddress)), // feeToken (ION)
		totalSupply,   // inputAmount
		totalSupply,   // outputAmount (1:1 at bonding curve start)
		big.NewInt(0), // fee
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack Swapped event")
	}
	// Pack PairRegistered event (ION ↔ Token)
	startPrice := big.NewInt(1e18) // 1
	endPrice := big.NewInt(1e18)   // 1
	pairRegisteredData, err := bondingcurve.ABI.Events["PairRegistered"].Inputs.NonIndexed().Pack(
		common.HexToAddress("0xdead"),
		startPrice,
		endPrice,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to pack PairRegistered event")
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
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
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
          "address": "0x{{.TokenFactoryContract}}",
          "data": "{{.BondedTokenCreatedData}}",
          "logIndex": "0x4",
          "removed": false,
          "topics": [
            "0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd",
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
          "data": "{{.PairRegisteredData}}",
          "logIndex": "0x6",
          "removed": false,
          "topics": [
            "0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c",
            "{{.Token.PairId}}",
            "0x000000000000000000000000{{.Token.BaseToken}}",
            "0x000000000000000000000000{{.Token.ContractAddress}}"
          ]
        },
        {
          "address": "{{.IONTokenAddress}}",
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
          "data": "{{.SwappedData}}",
          "logIndex": "0x9",
          "removed": false,
          "topics": [
            "0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81",
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
	tokenFactoryNoPrefix := strings.TrimPrefix(gen.TokenFactoryContractAddress, "0x")
	err = tmpl.Execute(buf, &dummyDataTemplateParams{
		Stream:                 stream,
		BlockNumber:            blockNum,
		BlockTimestamp:         uint64(time.Now().In(time.UTC).Add(-60 * time.Second).Unix()), // Create token 1 minute in the past
		TxIndex:                1,
		BlockHash:              blockHash,
		TxHash:                 txHash,
		Token:                  seedData,
		TxInput:                "0x83362e17" + hex.EncodeToString(txInput),
		ContentAuthorID:        ownerBlockchainAddr,
		BondingCurveContract:   bondingCurveNoPrefix,
		TokenFactoryContract:   tokenFactoryNoPrefix,
		BondedTokenCreatedData: "0x" + hex.EncodeToString(bondedTokenCreatedData),
		PairRegisteredData:     "0x" + hex.EncodeToString(pairRegisteredData),
		SwappedData:            "0x" + hex.EncodeToString(swappedData),
		IONTokenAddress:        strings.ToLower(gen.IONTokenAddress),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to insert dummy contract data: malformed template")
	}
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)`
	_, err = storage.Exec(ctx, gen.Target, sql, blockNum, stream, buf.String())
	if err != nil && !storage.IsErr(err, storage.ErrDuplicate) {
		return errors.Wrapf(err, "failed to insert dummy contract data")
	}
	return nil
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

	for existingAddr, existingMaster := range gen.userBlockChainToMaster {
		if existingMaster == masterPubkey {
			log.Info(fmt.Sprintf("User with masterPubkey %v already exists, reusing blockchain address 0x%v", masterPubkey, existingAddr))
			return existingAddr, masterPubkey, nil
		}
	}

	if len(gen.createdUsers) >= int(gen.MaxUsers) {
		userIdx := cryptoRandInt(len(gen.createdUsers))
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
	idx := cryptoRandInt(len(names))
	displayName := names[idx]
	usernameBase := strings.ToLower(strings.ReplaceAll(displayName, " ", ""))
	username := usernameBase + mustRandomHex(4)
	verified := cryptoRandInt(2) == 0
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
	avatarURL := avatarURLs[cryptoRandInt(len(avatarURLs))]

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
		ON CONFLICT (id) DO NOTHING
	`, id, masterPubkey, "0x"+blockchainAddress, externalAddress, username, displayName, avatarURL, lookup, ionConnectRelays, verified, platformGroup)
	if err != nil && !storage.IsErr(err, storage.ErrDuplicate) {
		return "", "", fmt.Errorf("failed to insert user %v: %w", masterPubkey, err)
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

func cryptoRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))

	return int(n.Int64())
}

func cryptoRandFloat64() float64 {
	max := big.NewInt(1 << 53)
	n, _ := rand.Int(rand.Reader, max)

	return float64(n.Int64()) / float64(max.Int64())
}

func (gen *dummyDataGenerator) generateP2PTransferBatch(ctx context.Context, stream string, token *tokenRow, totalTx int, platformGroup string) error {
	isRealToken := !strings.Contains(token.ContractAddress, "deadbeef")
	if isRealToken {
		stream = "00000000-0000-0000-0000-000000000000"
	}
	userPool, err := gen.getOrCreateTokenUserPool(ctx, token.ContractAddress, platformGroup)
	if err != nil {
		return errors.Wrapf(err, "failed to get user pool for token %s", token.ContractAddress)
	}
	if len(userPool) < 2 {
		return errors.Errorf("need at least 2 users for P2P transfers, got %d", len(userPool))
	}

	blockNum := atomic.AddUint64(&gen.InsertBlockIndex, 1)
	baseTimestamp := time.Now().In(time.UTC).Add(-30 * time.Second).Unix()

	tmpl, err := template.New("p2p_transfer").Parse(
		`{
  "accessList": [],
  "blockHash": "0x{{.BlockHash}}",
  "blockNumber": "{{.BlockNumber}}",
  "blockTimestamp": "{{.BlockTimestamp}}",
  "chainId": "0x61",
  "from": "0x{{.FromAddr}}",
  "gas": "0x5208",
  "gasPrice": "0x3b9aca00",
  "hash": "0x{{.TxHash}}",
  "input": "0xa9059cbb000000000000000000000000{{.ToAddr}}{{.AmountHex}}",
  "logs": [
    {
      "address": "0x{{.TokenContract}}",
      "data": "0x{{.AmountHex}}",
      "logIndex": "0x0",
      "removed": false,
      "topics": [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "0x000000000000000000000000{{.FromAddr}}",
        "0x000000000000000000000000{{.ToAddr}}"
      ]
    }
  ],
  "maxFeePerGas": "0x3b9aca00",
  "maxPriorityFeePerGas": "0x3b9aca00",
  "nonce": "0x{{.Nonce}}",
  "r": "0x1",
  "s": "0x1",
  "to": "0x{{.TokenContract}}",
  "transactionIndex": "0x{{.TxIndex}}",
  "type": "0x2",
  "v": "0x0",
  "value": "0x0",
  "yParity": "0x0"
}`)
	if err != nil {
		return errors.Wrapf(err, "failed to parse P2P transfer template")
	}

	txsForBlock := []string{}

	for txIdx := range totalTx {
		fromIdx := cryptoRandInt(len(userPool))
		toIdx := cryptoRandInt(len(userPool))
		for toIdx == fromIdx {
			toIdx = cryptoRandInt(len(userPool))
		}

		fromUser := userPool[fromIdx]
		toUser := userPool[toIdx]
		txTimestamp := uint64(baseTimestamp + int64(txIdx))

		minTokens := 1.0
		maxTokens := 1000.0
		tokensToTransfer := minTokens + cryptoRandFloat64()*(maxTokens-minTokens)

		transferAmountWei := new(big.Float).Mul(big.NewFloat(tokensToTransfer), big.NewFloat(1e18))
		transferAmount, _ := transferAmountWei.Int(nil)
		// Pad to 32 bytes hex
		amountHex := hex.EncodeToString(common.LeftPadBytes(transferAmount.Bytes(), 32))
		buf := bytes.NewBuffer([]byte{})
		execErr := tmpl.Execute(buf, map[string]any{
			"Stream":         stream,
			"BlockNumber":    blockNum,
			"BlockTimestamp": txTimestamp,
			"TxIndex":        fmt.Sprintf("%x", txIdx+1),
			"BlockHash":      mustRandomHex(32),
			"TxHash":         mustRandomHex(32),
			"FromAddr":       strings.TrimPrefix(fromUser.blockchainAddress, "0x"),
			"ToAddr":         strings.TrimPrefix(toUser.blockchainAddress, "0x"),
			"TokenContract":  strings.TrimPrefix(token.ContractAddress, "0x"),
			"AmountHex":      amountHex,
			"Nonce":          fmt.Sprintf("%x", cryptoRandInt(1000)),
		})

		if execErr != nil {
			return errors.Wrapf(execErr, "failed to execute P2P transfer template")
		}

		txsForBlock = append(txsForBlock, buf.String())

		log.Debug(fmt.Sprintf("Generated P2P transfer tx for token %s: from=%s to=%s amount=%s tokens",
			token.ContractAddress, fromUser.blockchainAddress, toUser.blockchainAddress, big.NewFloat(tokensToTransfer).String()))
	}

	fullData := fmt.Sprintf(`{"stream": "%[1]v", "transactions": [`+strings.Join(txsForBlock, ",")+`]}`, stream)
	sql := `INSERT INTO smart_contract_transactions(from_block_number, to_block_number, network, stream_id, data)
			VALUES ($1, $1, 'bsc-testnet-dummy', $2, $3::JSONB)
			ON CONFLICT (from_block_number, to_block_number, network) DO NOTHING`

	_, err = storage.Exec(ctx, gen.Target, sql, blockNum, stream, fullData)
	if err != nil && !storage.IsErr(err, storage.ErrDuplicate) {
		return errors.Wrapf(err, "failed to insert P2P transfer tx data")
	}

	log.Info(fmt.Sprintf("Generated %d P2P transfer transactions for token %s (block %d)",
		totalTx, token.ContractAddress, blockNum))

	return nil
}
