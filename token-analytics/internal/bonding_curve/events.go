// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ice-blockchain/wintr/log"
)

// TODO: Remove this once all transactions use the 5-parameter swap with permit.
const swap4ParamABIJSON = `[{"inputs":[{"internalType":"bytes","name":"fromToken","type":"bytes"},{"internalType":"bytes","name":"toToken","type":"bytes"},{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"minReturn","type":"uint256"}],"name":"swap","outputs":[],"stateMutability":"nonpayable","type":"function"}]`

var (
	abi4Param abi.ABI
)

func ProcessEvent(functionHex, data string, topics []string, contractAddress, txInput string) (Event, error) {
	switch functionHex {
	case eventTokenCreated.Hex():
		if len(topics) < 2 {
			return nil, errors.Errorf("TokenCreated event requires at least 2 topics, got %d", len(topics))
		}

		return tokenCreated(functionHex, data, contractAddress, topics[1])
	case eventSwapped.Hex():
		if len(topics) < 3 {
			return nil, errors.Errorf("Swapped event requires at least 3 topics, got %d", len(topics))
		}

		return tokenSwapped(functionHex, data, contractAddress, topics[1], topics[2], txInput)
	case eventPairRegistered.Hex():
		if len(topics) < 4 {
			return nil, errors.Errorf("PairRegistered event requires at least 4 topics, got %d", len(topics))
		}

		return pairRegistered(functionHex, data, topics[1], topics[2], topics[3])
	case eventRecipientsSet.Hex():
		return recipientsSet(functionHex, data)
	case eventFeeAccrued.Hex():
		return feeAccrued(functionHex, data)
	case eventFeeTransfer.Hex():
		if len(topics) < 3 {
			return nil, errors.Errorf("FeeTRansfer requires at least 3 topics, got %d", len(topics))
		}
		return feeTransfer(functionHex, data, topics[1], topics[2])
	case eventMigrated.Hex():
		if len(topics) < 2 {
			return nil, errors.Errorf("Migrated event requires at least 2 topics, got %d", len(topics))
		}
		return migrated(functionHex, data, topics[1])
	case eventLiquidityClaimed.Hex():
		return liquidityClaimed(functionHex, data)
	case eventSlippageChecked.Hex():
		if len(topics) < 2 {
			return nil, errors.Errorf("SlippageChecked event requires at least 2 topics, got %d", len(topics))
		}
		return slippageChecked(functionHex, data, topics[1])
	case eventLiquidityLocked.Hex():
		if len(topics) < 2 {
			return nil, errors.Errorf("LiquidityLocked event requires at least 3 topics, got %d", len(topics))
		}
		return liquidityLocked(functionHex, data, topics[1])
	case eventPoolCreated.Hex():
		if len(topics) < 4 {
			return nil, errors.Errorf("PoolCreated event requires at least 4 topics, got %d", len(topics))
		}
		return poolCreated(functionHex, data, topics[1], topics[2], topics[3])
	case eventUniswapSwapped.Hex():
		if len(topics) < 4 {
			return nil, errors.Errorf("PoolCreated event requires at least 4 topics, got %d", len(topics))
		}
		return uniswapSwapped(functionHex, data, topics[1], topics[2], contractAddress)
	default:
		log.Warn(fmt.Sprintf("Unknown event: %v, data: %v", functionHex, data))
	}

	return nil, nil
}

func decode[T any](abi abi.ABI, res T, name, data string) error {
	if len(data) > 0 && strings.HasPrefix(data, "0x") {
		binary, err := hex.DecodeString(data[2:])
		if err != nil {
			return errors.Wrapf(err, "failed to decode event data, invalid hex: %v", data[2:])
		}
		data = string(binary)
	}
	if err := abi.UnpackIntoInterface(res, name, []byte(data)); err != nil {
		return errors.Wrapf(err, "failed to unpack event")
	}
	return nil
}

func tokenCreated(signature, data, contractAddress, erc20TokenTopic string) (*LogTokenCreated, error) {
	if signature != eventTokenCreated.Hex() {
		return nil, errors.Errorf("invalid signature for BondedTokenCreated: expected %s, got %s", eventTokenCreated.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for BondedTokenCreated event")
	}

	var tokenCreatedEvent LogTokenCreated
	if err := decode(ABI, &tokenCreatedEvent, "BondingTokenCreated", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack BondedTokenCreated event")
	}
	tokenCreatedEvent.Address = common.HexToAddress(erc20TokenTopic)

	log.Debug(fmt.Sprintf("Token created: address=%v, externalAddress=%s, totalSupply=%v",
		tokenCreatedEvent.Address.Hex(), tokenCreatedEvent.ExternalAddress, tokenCreatedEvent.TotalSupply))

	return &tokenCreatedEvent, nil
}

func pairRegistered(signature, data, pairIdTopic, baseTokenTopic, otherTokenTopic string) (*LogPairRegistered, error) {
	if signature != eventPairRegistered.Hex() {
		return nil, errors.Errorf("invalid signature for PairRegistered: expected %s, got %s", eventPairRegistered.Hex(), signature)
	}

	var pairRegisteredEvent LogPairRegistered
	pairRegisteredEvent.PairId = common.HexToHash(pairIdTopic)
	pairRegisteredEvent.BaseToken = common.HexToAddress(baseTokenTopic)
	pairRegisteredEvent.OtherToken = common.HexToAddress(otherTokenTopic)

	if err := decode(ABI, &pairRegisteredEvent, "PairRegistered", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack PairRegistered event data")
	}

	log.Debug(fmt.Sprintf("Pair registered: pairId=%x, baseToken=%s, otherToken=%s, priceModel=%s, startPrice=%v, endPrice=%v",
		pairRegisteredEvent.PairId, pairRegisteredEvent.BaseToken.Hex(), pairRegisteredEvent.OtherToken.Hex(),
		pairRegisteredEvent.PriceModel.Hex(), pairRegisteredEvent.StartPrice, pairRegisteredEvent.EndPrice))

	return &pairRegisteredEvent, nil
}

func parseHandleOps(txInput string) (*CustomHandleOps, error) {
	// Remove "0x" prefix and function selector (4 bytes = 8 hex chars)
	hexData := strings.TrimPrefix(txInput, "0x")
	if len(hexData) < 8 {
		return nil, errors.New("tx input too short for handleOps")
	}
	// Structure:
	// [0:8]   - selector (0x74fa4121)
	// [8:72]  - offset to userOps (always 0x60 = 96 bytes)
	// [72:136] - r (signature part 1)
	// [136:200] - vs (signature part 2, EIP-2098 compact)
	// [200:264] - userOps length in bytes
	// [264:...] - userOps data: sender(20) + nonce(32) + callDataLength(32) + callData

	if len(hexData) < 264 {
		return nil, errors.New("tx input too short for handleOps with userOps")
	}

	// Skip selector and read userOps offset (should be 96 bytes = 0x60)
	userOpsOffsetHex := hexData[8:72]
	userOpsOffset, err := strconv.ParseUint(userOpsOffsetHex[len(userOpsOffsetHex)-8:], 16, 32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse userOps offset")
	}
	// userOps starts at byte offset (in hex chars = offset * 2)
	userOpsStartHex := int(userOpsOffset * 2)
	if len(hexData) < userOpsStartHex+64 {
		return nil, errors.New("tx input too short for userOps length")
	}
	// Read userOps length (32 bytes at userOpsStartHex)
	userOpsLengthHex := hexData[userOpsStartHex : userOpsStartHex+64]
	userOpsLength, err := strconv.ParseUint(userOpsLengthHex[len(userOpsLengthHex)-8:], 16, 32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse userOps length")
	}
	// UserOps data starts right after length field
	userOpsDataStart := userOpsStartHex + 64

	// Ensure userOpsLength fits into an int before converting and using it for indexing.
	if userOpsLength > uint64(math.MaxInt) {
		return nil, errors.New("userOps length too large")
	}
	userOpsLengthInt := int(userOpsLength)
	userOpsDataEnd := userOpsDataStart + userOpsLengthInt*2
	if userOpsDataEnd > len(hexData) {
		return nil, errors.New("tx input too short for userOps data")
	}
	userOpsDataHex := hexData[userOpsDataStart:userOpsDataEnd]

	// Parse UserOps structure:
	// [0:40]   - sender (20 bytes)
	// [40:104] - nonce (32 bytes)
	// [104:168] - callDataLength (32 bytes)
	// [168:...] - callData
	if len(userOpsDataHex) < 168 {
		return nil, errors.New("userOps data too short")
	}
	sender := common.HexToAddress("0x" + userOpsDataHex[0:40])
	nonceHex := userOpsDataHex[40:104]
	nonce := new(big.Int)
	nonce.SetString(nonceHex, 16)

	callDataLengthHex := userOpsDataHex[104:168]
	callDataLength, err := strconv.ParseUint(callDataLengthHex[len(callDataLengthHex)-8:], 16, 32)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse callData length")
	}

	if callDataLength > uint64(int(math.MaxInt64)) {
		return nil, errors.Errorf("callData length too large: %d", callDataLength)
	}

	// Extract callData
	callDataStart := 168
	callDataEnd := callDataStart + int(callDataLength)*2
	if len(userOpsDataHex) < callDataEnd {
		return nil, errors.Errorf("userOps data too short for callData: need %d, have %d", callDataEnd, len(userOpsDataHex))
	}

	callDataHex := userOpsDataHex[callDataStart:callDataEnd]
	callData, err := hex.DecodeString(callDataHex)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode callData")
	}
	result := &CustomHandleOps{
		Ops: []CustomUserOperation{
			{
				Sender:   sender,
				Nonce:    nonce,
				CallData: callData,
			},
		},
	}

	return result, nil
}

func tokenSwapped(signature, data, contractAddress, swapperTopic, pairIdTopic, txInput string) (*LogTokenSwapped, error) {
	if signature != eventSwapped.Hex() {
		return nil, errors.Errorf("invalid signature for Swapped: expected %s, got %s", eventSwapped.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for Swapped event")
	}
	var tokenSwappedEvent LogTokenSwapped
	if err := decode(ABI, &tokenSwappedEvent, "Swapped", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack Swapped event")
	}
	tokenSwappedEvent.Swapper = common.HexToAddress(swapperTopic)
	tokenSwappedEvent.Pair = common.HexToHash(pairIdTopic)

	if len(txInput) < 10 {
		log.Debug(fmt.Sprintf("Token swapped: swapper=%v, pair=%v, direction=%v (no tx input params - tx too short, len=%d)",
			tokenSwappedEvent.Swapper.Hex(), tokenSwappedEvent.Pair.Hex(), tokenSwappedEvent.Direction, len(txInput)))
		return &tokenSwappedEvent, nil
	}

	functionSelector := txInput[:10]
	log.Debug(fmt.Sprintf("Processing swap with function selector: %s, txInput length: %d", functionSelector, len(txInput)))

	// Function selectors:
	// handleOps (custom implementation) = 0x74fa4121
	// swap(bytes,bytes,uint256,uint256) = 0x83362e17
	// swap(bytes,bytes,uint256,uint256,(uint256,uint256,uint8,bytes32,bytes32)) = 0x027c101d
	const (
		handleOpsSelector  = "0x74fa4121" // Custom: handleOps(bytes,uint256,uint256)
		swap4ParamSelector = "0x83362e17"
		swap5ParamSelector = "0x027c101d"
	)

	// If this is a custom handleOps transaction, extract the inner calldata
	if functionSelector == handleOpsSelector {
		// Custom handleOps implementation with simplified structure:
		// function handleOps(
		//     bytes memory userOps,  // Single UserOperation: sender(20) + nonce(32) + callDataLength(32) + callData
		//     uint256 r,             // Signature component 1
		//     uint256 vs             // Signature component 2 (EIP-2098 compact)
		// )
		//
		originalTxInput := txInput

		handleOpsData, err := parseHandleOps(originalTxInput)
		if err != nil {
			log.Debug(fmt.Sprintf("Custom handleOps full parse failed (expected for truncated data): %v", err))
		} else {
			tokenSwappedEvent.CustomHandleOp = handleOpsData
			log.Debug(fmt.Sprintf("✓ Parsed custom handleOps: sender=%s, nonce=%s",
				handleOpsData.Ops[0].Sender.Hex(), handleOpsData.Ops[0].Nonce.String()))
		}

		// Search for swap selectors within the txInput to extract the actual swap() call
		swap4Pos := strings.Index(txInput, swap4ParamSelector[2:]) // Remove "0x" prefix
		swap5Pos := strings.Index(txInput, swap5ParamSelector[2:])

		if swap4Pos > 0 {
			// Found 4-param swap selector, extract from this position
			txInput = "0x" + txInput[swap4Pos:]
			functionSelector = swap4ParamSelector
			log.Debug(fmt.Sprintf("Extracted 4-param swap from custom handleOps at position %d, new length: %d", swap4Pos, len(txInput)))
		} else if swap5Pos > 0 {
			// Found 5-param swap selector
			txInput = "0x" + txInput[swap5Pos:]
			functionSelector = swap5ParamSelector
			log.Debug(fmt.Sprintf("Extracted 5-param swap from custom handleOps at position %d, new length: %d", swap5Pos, len(txInput)))
		} else {
			// No swap selector found in handleOps
			log.Debug(fmt.Sprintf("Token swapped: swapper=%v, pair=%v, direction=%v (no swap selector found in custom handleOps)",
				tokenSwappedEvent.Swapper.Hex(), tokenSwappedEvent.Pair.Hex(), tokenSwappedEvent.Direction))
			return &tokenSwappedEvent, nil
		}
	}

	if functionSelector != swap4ParamSelector && functionSelector != swap5ParamSelector {
		log.Debug(fmt.Sprintf("Token swapped: swapper=%v, pair=%v, direction=%v (no tx input params - not a swap function, selector=%s)",
			tokenSwappedEvent.Swapper.Hex(), tokenSwappedEvent.Pair.Hex(), tokenSwappedEvent.Direction, functionSelector))
		return &tokenSwappedEvent, nil
	}

	// Decode swap function parameters based on the selector
	swapParams := make(map[string]any)
	decodedTxInput, err := hex.DecodeString(txInput[10:])
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse tx input hex: %v", txInput[10:])
	}

	// Use the correct ABI based on function selector
	switch functionSelector {
	case swap5ParamSelector:
		// 5-param version: swap(bytes,bytes,uint256,uint256,PermitData)
		method5, ok := ABI.Methods["swap"]
		if !ok {
			log.Panic(errors.Errorf("failed to find 5-param swap method in bonding curve abi"))
		}
		err = method5.Inputs.UnpackIntoMap(swapParams, decodedTxInput)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse 5-param swap tx input")
		}
	case swap4ParamSelector:
		// 4-param version: swap(bytes,bytes,uint256,uint256)
		method4, ok := abi4Param.Methods["swap"]
		if !ok {
			log.Panic(errors.Errorf("failed to find 4-param swap method in abi"))
		}
		err = method4.Inputs.UnpackIntoMap(swapParams, decodedTxInput)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse 4-param swap tx input")
		}
	default:
		return nil, errors.Errorf("unexpected function selector: %s", functionSelector)
	}

	tokenSwappedEvent.Params = swapParams
	log.Debug(fmt.Sprintf("Token swapped: swapper=%v, pair=%v, direction=%v",
		tokenSwappedEvent.Swapper.Hex(), tokenSwappedEvent.Pair.Hex(),
		tokenSwappedEvent.Direction))

	return &tokenSwappedEvent, nil
}

func recipientsSet(signature, data string) (*LogRecipientsSet, error) {
	if signature != eventRecipientsSet.Hex() {
		return nil, errors.Errorf("invalid signature for RecipientsSet: expected %s, got %s", eventRecipientsSet.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for RecipientsSet event")
	}
	var recipientsSetEvent LogRecipientsSet
	if err := decode(ABI, &recipientsSetEvent, "RecipientsSet", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack RecipientsSet event")
	}
	log.Debug(fmt.Sprintf("Recipients set: pairId=%x, creator=%s", recipientsSetEvent.PairId, recipientsSetEvent.Creator.Hex()))

	return &recipientsSetEvent, nil
}

func feeAccrued(signature, data string) (*LogFeeAccrued, error) {
	if signature != eventFeeAccrued.Hex() {
		return nil, errors.Errorf("invalid signature for FeeAccrued: expected %s, got %s", eventFeeAccrued.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for FeeAccrued event")
	}
	var feeAccruedEvent LogFeeAccrued
	if err := decode(ABI, &feeAccruedEvent, "FeeAccrued", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack FeeAccrued event")
	}
	log.Debug(fmt.Sprintf("Fee accrued: pairId=%x", feeAccruedEvent.PairId))

	return &feeAccruedEvent, nil
}

func feeTransfer(signature, data, pairIdTopic, toTopic string) (*LogFeeTransfer, error) {
	if signature != eventFeeTransfer.Hex() {
		return nil, errors.Errorf("invalid signature for FeeTransfer: expected %s, got %s", eventFeeTransfer.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for FeeTransfer event")
	}
	var feeTransferEvent LogFeeTransfer
	if err := decode(ABI, &feeTransferEvent, "FeeTransfer", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack FeeTransfer event")
	}
	feeTransferEvent.PairId = common.HexToHash(pairIdTopic)
	feeTransferEvent.To = common.HexToAddress(toTopic)
	log.Debug(fmt.Sprintf("Fee transfer: pairId=%x to=%x amount=%d", feeTransferEvent.PairId, feeTransferEvent.To, feeTransferEvent.Amount))

	return &feeTransferEvent, nil
}

func migrated(signature, data, pairId string) (*LogMigrated, error) {
	if signature != eventMigrated.Hex() {
		return nil, errors.Errorf("invalid signature for Migrated: expected %s, got %s", eventMigrated.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for Migrated event")
	}
	var migratedEvent LogMigrated
	migratedEvent.PairId = common.HexToHash(pairId)
	if err := decode(ABI, &migratedEvent, "Migrated", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack Migrated event")
	}
	log.Debug(fmt.Sprintf("Migrated: pairId=%x", migratedEvent.PairId))

	return &migratedEvent, nil
}

func liquidityClaimed(signature, data string) (*LogLiquidityClaimed, error) {
	if signature != eventLiquidityClaimed.Hex() {
		return nil, errors.Errorf("invalid signature for LiquidityClaimed: expected %s, got %s", eventLiquidityClaimed.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for LiquidityClaimed event")
	}
	var liquidityClaimedEvent LogLiquidityClaimed
	if err := decode(ABI, &liquidityClaimedEvent, "LiquidityClaimed", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack LiquidityClaimed event")
	}
	log.Debug(fmt.Sprintf("Liquidity claimed: pairId=%x", liquidityClaimedEvent.PairId))

	return &liquidityClaimedEvent, nil
}

func slippageChecked(signature, data, pairId string) (*LogSlippageChecked, error) {
	if signature != eventSlippageChecked.Hex() {
		return nil, errors.Errorf("invalid signature for SlippageChecked: expected %s, got %s", eventSlippageChecked.Hex(), signature)
	}
	if pairId == "" || pairId == "0x" {
		return nil, errors.Errorf("empty pairId for SlippageChecked event")
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for SlippageChecked event")
	}

	var slippageEvent LogSlippageChecked
	pairIdBytes, err := hex.DecodeString(strings.TrimPrefix(pairId, "0x"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode pairId")
	}
	copy(slippageEvent.PairId[:], pairIdBytes)

	dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode slippage data")
	}

	if len(dataBytes) < 64 {
		return nil, errors.Errorf("insufficient data for SlippageChecked: expected 64 bytes, got %d", len(dataBytes))
	}
	slippageEvent.MinReturn = new(big.Int).SetBytes(dataBytes[0:32])
	slippageEvent.ActualOut = new(big.Int).SetBytes(dataBytes[32:64])

	log.Info(fmt.Sprintf("SlippageChecked: pairId=%x, minReturn=%v, actualOut=%v",
		slippageEvent.PairId, slippageEvent.MinReturn, slippageEvent.ActualOut))

	return &slippageEvent, nil
}

func liquidityLocked(signature, data, pairId string) (*LogLiquidityLocked, error) {
	if signature != eventLiquidityLocked.Hex() {
		return nil, errors.Errorf("invalid signature for LiquidityLocked: expected %s, got %s", eventLiquidityLocked.Hex(), signature)
	}
	if pairId == "" || pairId == "0x" {
		return nil, errors.Errorf("empty pairId for LiquidityLocked event")
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for LiquidityLocked event")
	}

	var liquidityEvent LogLiquidityLocked
	liquidityEvent.PairId = common.HexToHash(pairId)

	dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode liquidity data")
	}

	if len(dataBytes) < 96 {
		return nil, errors.Errorf("insufficient data for LiquidityLocked: expected 64 bytes, got %d", len(dataBytes))
	}
	liquidityEvent.LpToken = common.BytesToAddress(dataBytes[0:32])
	liquidityEvent.Amount = new(big.Int).SetBytes(dataBytes[32:64])
	liquidityEvent.UnlockTime = new(big.Int).SetBytes(dataBytes[64:96])

	log.Info(fmt.Sprintf("LiquidityLocked: pairId=%x, lpToken=%v, amount=%v, unlockTime=%v",
		liquidityEvent.PairId, liquidityEvent.LpToken.Hex(), liquidityEvent.Amount, liquidityEvent.UnlockTime))

	return &liquidityEvent, nil
}

func poolCreated(signature, data, token0, token1, fee string) (*LogPoolCreated, error) {
	if signature != eventPoolCreated.Hex() {
		return nil, errors.Errorf("invalid signature for PoolCreated: expected %s, got %s", eventPoolCreated.Hex(), signature)
	}
	if token0 == "" || token0 == "0x" {
		return nil, errors.Errorf("empty token0 for PoolCreated event")
	}
	if token1 == "" || token1 == "0x" {
		return nil, errors.Errorf("empty token1 for PoolCreated event")
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for PoolCreated event")
	}

	var logPoolCreated LogPoolCreated
	if err := decode(UniswapABI, &logPoolCreated, "PoolCreated", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack PoolCreated event")
	}
	logPoolCreated.Token0 = common.HexToAddress(token0)
	logPoolCreated.Token1 = common.HexToAddress(token1)
	logPoolCreated.Fee, _ = big.NewInt(0).SetString(fee, 16)

	return &logPoolCreated, nil
}

func uniswapSwapped(signature, data, sender, recipient, pool string) (*LogUniswapSwapped, error) {
	if signature != eventUniswapSwapped.Hex() {
		return nil, errors.Errorf("invalid signature for UniswapSwapped: expected %s, got %s", eventUniswapSwapped.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for UniswapSwapped event")
	}

	var logUniswapSwapped LogUniswapSwapped
	if err := decode(ABI, &logUniswapSwapped, "Swap", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack Swap event")
	}

	logUniswapSwapped.Sender = common.HexToAddress(sender)
	logUniswapSwapped.Recipient = common.HexToAddress(recipient)
	logUniswapSwapped.PoolAddress = common.HexToAddress(pool)
	log.Debug(fmt.Sprintf("Uniswap Swapped: sender=%s, recipient=%s, amount0=%v, amount1=%v",
		logUniswapSwapped.Sender.Hex(), logUniswapSwapped.Recipient.Hex(), logUniswapSwapped.Amount0, logUniswapSwapped.Amount1))

	return &logUniswapSwapped, nil
}
