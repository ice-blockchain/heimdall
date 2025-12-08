// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
)

func init() {
	var err error
	ABI, err = abi.JSON(strings.NewReader(ABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse bonding curve abi"))
}

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
		return feeTransfer(functionHex, data)
	case eventMigrated.Hex():
		return migrated(functionHex, data)
	case eventLiquidityClaimed.Hex():
		return liquidityClaimed(functionHex, data)
	case eventSlippageChecked.Hex():
		if len(topics) < 2 {
			return nil, errors.Errorf("SlippageChecked event requires at least 2 topics, got %d", len(topics))
		}
		return slippageChecked(functionHex, data, topics[1])
	case eventLiquidityLocked.Hex():
		if len(topics) < 3 {
			return nil, errors.Errorf("LiquidityLocked event requires at least 3 topics, got %d", len(topics))
		}
		return liquidityLocked(functionHex, data, topics[1], topics[2])
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
	if data != "" && data != "0x" {
		var pairRegisteredEvent LogPairRegistered
		if err := decode(ABI, &pairRegisteredEvent, "PairRegistered", data); err != nil {
			return nil, errors.Wrapf(err, "failed to unpack PairRegistered event")
		}
		log.Debug(fmt.Sprintf("Pair registered: pairId=%x, baseToken=%s, otherToken=%s", pairRegisteredEvent.PairId, pairRegisteredEvent.BaseToken.Hex(), pairRegisteredEvent.OtherToken.Hex()))
		return &pairRegisteredEvent, nil
	}
	log.Info("Pair registered (empty data, all params indexed)")

	var pairRegisteredEvent LogPairRegistered
	pairRegisteredEvent.PairId = common.HexToHash(pairIdTopic)
	pairRegisteredEvent.BaseToken = common.HexToAddress(baseTokenTopic)
	pairRegisteredEvent.OtherToken = common.HexToAddress(otherTokenTopic)

	log.Debug(fmt.Sprintf("Pair registered: pairId=%x, baseToken=%v, otherToken=%v",
		pairRegisteredEvent.PairId, pairRegisteredEvent.BaseToken.Hex(), pairRegisteredEvent.OtherToken.Hex()))

	return &pairRegisteredEvent, nil
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
	tokenSwappedEvent.Address = common.HexToAddress(contractAddress)
	tokenSwappedEvent.Swapper = common.HexToAddress(swapperTopic)
	tokenSwappedEvent.Pair = common.HexToHash(pairIdTopic)
	if len(txInput) < 10 {
		return nil, errors.Errorf("swap: tx input too short")
	}
	tokenSwapParams := make(map[string]any)
	decodedTxInput, err := hex.DecodeString(txInput[10:])
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse tx input hex: %v", txInput[10:])
	}

	method, ok := ABI.Methods["swap"]
	if !ok {
		return nil, errors.Errorf("failed to find swap method in bonding curve abi")
	}
	err = method.Inputs.UnpackIntoMap(tokenSwapParams, decodedTxInput)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse tx input")
	}
	tokenSwappedEvent.Params = tokenSwapParams
	log.Debug(fmt.Sprintf("Token swapped: token=%v, swapper=%v, pair=%v, direction=%v",
		tokenSwappedEvent.Address.Hex(), tokenSwappedEvent.Swapper.Hex(), tokenSwappedEvent.Pair.Hex(),
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

func feeTransfer(signature, data string) (*LogFeeTransfer, error) {
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
	log.Debug(fmt.Sprintf("Fee transfer: pairId=%x", feeTransferEvent.PairId))

	return &feeTransferEvent, nil
}

func migrated(signature, data string) (*LogMigrated, error) {
	if signature != eventMigrated.Hex() {
		return nil, errors.Errorf("invalid signature for Migrated: expected %s, got %s", eventMigrated.Hex(), signature)
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for Migrated event")
	}
	var migratedEvent LogMigrated
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

func liquidityLocked(signature, data, pairId, lpToken string) (*LogLiquidityLocked, error) {
	if signature != eventLiquidityLocked.Hex() {
		return nil, errors.Errorf("invalid signature for LiquidityLocked: expected %s, got %s", eventLiquidityLocked.Hex(), signature)
	}
	if pairId == "" || pairId == "0x" {
		return nil, errors.Errorf("empty pairId for LiquidityLocked event")
	}
	if lpToken == "" || lpToken == "0x" {
		return nil, errors.Errorf("empty lpToken for LiquidityLocked event")
	}
	if data == "" || data == "0x" {
		return nil, errors.Errorf("empty data for LiquidityLocked event")
	}

	var liquidityEvent LogLiquidityLocked
	pairIdBytes, err := hex.DecodeString(strings.TrimPrefix(pairId, "0x"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode pairId")
	}
	copy(liquidityEvent.PairId[:], pairIdBytes)

	liquidityEvent.LpToken = common.HexToAddress(lpToken)

	dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode liquidity data")
	}

	if len(dataBytes) < 64 {
		return nil, errors.Errorf("insufficient data for LiquidityLocked: expected 64 bytes, got %d", len(dataBytes))
	}
	liquidityEvent.Amount = new(big.Int).SetBytes(dataBytes[0:32])
	liquidityEvent.UnlockTime = new(big.Int).SetBytes(dataBytes[32:64])

	log.Info(fmt.Sprintf("LiquidityLocked: pairId=%x, lpToken=%v, amount=%v, unlockTime=%v",
		liquidityEvent.PairId, liquidityEvent.LpToken.Hex(), liquidityEvent.Amount, liquidityEvent.UnlockTime))

	return &liquidityEvent, nil
}
