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
	bondingCurveABI, err = abi.JSON(strings.NewReader(bondingCurveABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse bonding curve abi"))
}

func ProcessEvent(functionHex, data string, topics []string) (Event, error) {
	switch functionHex {
	case eventTokenCreated.Hex():
		return tokenCreated(data)
	case eventSwapped.Hex():
		return tokenSwapped(data)
	case eventPairRegistered.Hex():
		return pairRegistered(data)
	case eventRecipientsSet.Hex():
		return recipientsSet(data)
	case eventFeeAccrued.Hex():
		return feeAccrued(data)
	case eventFeeTransfer.Hex():
		return feeTransfer(data)
	case eventMigrated.Hex():
		return migrated(data)
	case eventLiquidityClaimed.Hex():
		return liquidityClaimed(data)
	case eventTransfer.Hex():
		return transfer(data, topics)
	case eventOwnershipTransferred.Hex():
		return ownershipTransferred(data, topics)
	case eventSlippageChecked.Hex():
		return slippageChecked(data, topics)
	case eventLiquidityLocked.Hex():
		return liquidityLocked(data, topics)
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
		return errors.Wrapf(err, "failed to unpack BondedTokenCreated event")
	}
	return nil
}

func tokenCreated(data string) (*LogTokenCreated, error) {
	var tokenCreatedEvent LogTokenCreated
	if err := decode(bondingCurveABI, &tokenCreatedEvent, "BondedTokenCreated", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack BondedTokenCreated event")
	}
	log.Info(fmt.Sprintf("Token created:%+v ", tokenCreatedEvent))
	return &tokenCreatedEvent, nil
}

func pairRegistered(data string) (*LogPairRegistered, error) {
	var pairRegisteredEvent LogPairRegistered
	if err := decode(bondingCurveABI, &pairRegisteredEvent, "PairRegistered", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack PairRegistered event")
	}
	log.Info(fmt.Sprintf("Pair registered:%+v ", pairRegisteredEvent))
	return &pairRegisteredEvent, nil
}

func tokenSwapped(data string) (*LogTokenSwapped, error) {
	var tokenSwappedEvent LogTokenSwapped
	if err := decode(bondingCurveABI, &tokenSwappedEvent, "Swapped", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack Swapped event")
	}
	log.Info(fmt.Sprintf("Token swapped:%+v ", tokenSwappedEvent))
	return &tokenSwappedEvent, nil
}

func recipientsSet(data string) (*LogRecipientsSet, error) {
	var recipientsSetEvent LogRecipientsSet
	if err := decode(bondingCurveABI, &recipientsSetEvent, "RecipientsSet", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack RecipientsSet event")
	}
	log.Info(fmt.Sprintf("Recipients set:%+v ", recipientsSetEvent))
	return &recipientsSetEvent, nil
}

func feeAccrued(data string) (*LogFeeAccrued, error) {
	var feeAccruedEvent LogFeeAccrued
	if err := decode(bondingCurveABI, &feeAccruedEvent, "FeeAccrued", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack FeeAccrued event")
	}
	log.Info(fmt.Sprintf("Fee accrued:%+v ", feeAccruedEvent))
	return &feeAccruedEvent, nil
}

func feeTransfer(data string) (*LogFeeTransfer, error) {
	var feeTransferEvent LogFeeTransfer
	if err := decode(bondingCurveABI, &feeTransferEvent, "FeeTransfer", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack FeeTransfer event")
	}
	log.Info(fmt.Sprintf("Fee transfer:%+v ", feeTransferEvent))
	return &feeTransferEvent, nil
}

func migrated(data string) (*LogMigrated, error) {
	var migratedEvent LogMigrated
	if err := decode(bondingCurveABI, &migratedEvent, "Migrated", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack Migrated event")
	}
	log.Info(fmt.Sprintf("Migrated:%+v ", migratedEvent))
	return &migratedEvent, nil
}

func liquidityClaimed(data string) (*LogLiquidityClaimed, error) {
	var liquidityClaimedEvent LogLiquidityClaimed
	if err := decode(bondingCurveABI, &liquidityClaimedEvent, "LiquidityClaimed", data); err != nil {
		return nil, errors.Wrapf(err, "failed to unpack LiquidityClaimed event")
	}
	log.Info(fmt.Sprintf("Liquidity claimed:%+v ", liquidityClaimedEvent))

	return &liquidityClaimedEvent, nil
}

func transfer(data string, topics []string) (*LogTransfer, error) {
	var transferEvent LogTransfer

	// Transfer(address indexed from, address indexed to, uint256 amount)
	// topics[0] = event signature
	// topics[1] = from (indexed)
	// topics[2] = to (indexed)
	// data = amount (non-indexed)

	if len(topics) >= 3 {
		transferEvent.From = common.HexToAddress(topics[1])
		transferEvent.To = common.HexToAddress(topics[2])
	}

	if len(data) > 2 {
		amount := new(big.Int)
		dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode transfer data")
		}
		amount.SetBytes(dataBytes)
		transferEvent.Amount = amount
	} else {
		transferEvent.Amount = big.NewInt(0)
	}

	log.Info(fmt.Sprintf("Transfer: from=%v, to=%v, amount=%v",
		transferEvent.From.Hex(), transferEvent.To.Hex(), transferEvent.Amount))

	return &transferEvent, nil
}

func ownershipTransferred(data string, topics []string) (*LogOwnershipTransferred, error) {
	var ownershipEvent LogOwnershipTransferred

	// OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	// topics[0] = event signature
	// topics[1] = previousOwner (indexed)
	// topics[2] = newOwner (indexed)

	if len(topics) >= 3 {
		ownershipEvent.PreviousOwner = common.HexToAddress(topics[1])
		ownershipEvent.NewOwner = common.HexToAddress(topics[2])
	}

	log.Info(fmt.Sprintf("OwnershipTransferred: previousOwner=%v, newOwner=%v",
		ownershipEvent.PreviousOwner.Hex(), ownershipEvent.NewOwner.Hex()))

	return &ownershipEvent, nil
}

func slippageChecked(data string, topics []string) (*LogSlippageChecked, error) {
	var slippageEvent LogSlippageChecked

	// SlippageChecked(bytes32 indexed pairId, uint256 minReturn, uint256 actualOut)
	// topics[0] = event signature
	// topics[1] = pairId (indexed)
	// data = minReturn + actualOut (non-indexed, 32 bytes each)

	if len(topics) >= 2 {
		pairIdBytes, err := hex.DecodeString(strings.TrimPrefix(topics[1], "0x"))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode pairId")
		}
		copy(slippageEvent.PairId[:], pairIdBytes)
	}

	if len(data) > 2 {
		dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode slippage data")
		}

		if len(dataBytes) >= 64 {
			slippageEvent.MinReturn = new(big.Int).SetBytes(dataBytes[0:32])
			slippageEvent.ActualOut = new(big.Int).SetBytes(dataBytes[32:64])
		}
	}

	log.Info(fmt.Sprintf("SlippageChecked: pairId=%x, minReturn=%v, actualOut=%v",
		slippageEvent.PairId, slippageEvent.MinReturn, slippageEvent.ActualOut))

	return &slippageEvent, nil
}

func liquidityLocked(data string, topics []string) (*LogLiquidityLocked, error) {
	var liquidityEvent LogLiquidityLocked

	// LiquidityLocked(bytes32 indexed pairId, address indexed lpToken, uint256 amount, uint256 unlockTime)
	// topics[0] = event signature
	// topics[1] = pairId (indexed)
	// topics[2] = lpToken (indexed)
	// data = amount + unlockTime (non-indexed, 32 bytes each)

	if len(topics) >= 3 {
		pairIdBytes, err := hex.DecodeString(strings.TrimPrefix(topics[1], "0x"))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode pairId")
		}
		copy(liquidityEvent.PairId[:], pairIdBytes)

		liquidityEvent.LpToken = common.HexToAddress(topics[2])
	}

	if len(data) > 2 {
		dataBytes, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode liquidity data")
		}

		if len(dataBytes) >= 64 {
			liquidityEvent.Amount = new(big.Int).SetBytes(dataBytes[0:32])
			liquidityEvent.UnlockTime = new(big.Int).SetBytes(dataBytes[32:64])
		}
	}

	log.Info(fmt.Sprintf("LiquidityLocked: pairId=%x, lpToken=%v, amount=%v, unlockTime=%v",
		liquidityEvent.PairId, liquidityEvent.LpToken.Hex(), liquidityEvent.Amount, liquidityEvent.UnlockTime))

	return &liquidityEvent, nil
}
