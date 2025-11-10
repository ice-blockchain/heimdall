// SPDX-License-Identifier: ice License 1.0

package bondingcurve

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ice-blockchain/wintr/log"
	"github.com/pkg/errors"
)

func init() {
	var err error
	bondingCurveABI, err = abi.JSON(strings.NewReader(bondingCurveABIJSON))
	log.Panic(errors.Wrapf(err, "failed to parse bonding curve abi"))
}

func ProcessEvent(functionHex, data string) (error, Event) {
	switch functionHex {
	case eventTokenCreated.Hex():
		return tokenCreated(data)
	case eventSwapped.Hex():
		return tokenSwapped(data)
	case eventPairRegistered.Hex():
		return pairRegistered(data)
	case eventBought.Hex():
		return tokenBought(data)
	case eventSold.Hex():
		return tokenSold(data)
	case eventRecipientsSet.Hex():
		return recipientsSet(data)
	case eventFeeAccrued.Hex():
		return feeAccrued(data)
	case eventFeeTransfer.Hex():
		return feeTransfer(data)
	case eventMigrated.Hex():
		return migrated(data)
	case eventLPClaimed.Hex():
		return lpClaimed(data)
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

func tokenCreated(data string) (error, *LogTokenCreated) {
	var tokenCreatedEvent LogTokenCreated
	if err := decode[*LogTokenCreated](bondingCurveABI, &tokenCreatedEvent, "BondedTokenCreated", data); err != nil {
		return errors.Wrapf(err, "failed to unpack BondedTokenCreated event"), nil
	}
	log.Info(fmt.Sprintf("Token created:%+v ", tokenCreatedEvent))
	return nil, &tokenCreatedEvent
}

func pairRegistered(data string) (error, *LogPairRegistered) {
	var pairRegisteredEvent LogPairRegistered
	if err := decode[*LogPairRegistered](bondingCurveABI, &pairRegisteredEvent, "PairRegistered", data); err != nil {
		return errors.Wrapf(err, "failed to unpack PairRegistered event"), nil
	}
	log.Info(fmt.Sprintf("Pair registered:%+v ", pairRegisteredEvent))
	return nil, &pairRegisteredEvent
}

func tokenSwapped(data string) (error, *LogTokenSwapped) {
	var tokenSwappedEvent LogTokenSwapped
	if err := decode[*LogTokenSwapped](bondingCurveABI, &tokenSwappedEvent, "Swapped", data); err != nil {
		return errors.Wrapf(err, "failed to unpack Swapped event"), nil
	}
	log.Info(fmt.Sprintf("Token swapped:%+v ", tokenSwappedEvent))
	return nil, &tokenSwappedEvent
}

func tokenBought(data string) (error, *LogTokenBought) {
	var tokenBoughtEvent LogTokenBought
	if err := decode[*LogTokenBought](bondingCurveABI, &tokenBoughtEvent, "Bought", data); err != nil {
		return errors.Wrapf(err, "failed to unpack Bought event"), nil
	}
	log.Info(fmt.Sprintf("Token bought:%+v ", tokenBoughtEvent))
	return nil, &tokenBoughtEvent
}

func tokenSold(data string) (error, *LogTokenSold) {
	var tokenSoldEvent LogTokenSold
	if err := decode[*LogTokenSold](bondingCurveABI, &tokenSoldEvent, "Sold", data); err != nil {
		return errors.Wrapf(err, "failed to unpack Sold event"), nil
	}
	log.Info(fmt.Sprintf("Token sold:%+v ", tokenSoldEvent))
	return nil, &tokenSoldEvent
}

func recipientsSet(data string) (error, *LogRecipientsSet) {
	var recipientsSetEvent LogRecipientsSet
	if err := decode[*LogRecipientsSet](bondingCurveABI, &recipientsSetEvent, "RecipientsSet", data); err != nil {
		return errors.Wrapf(err, "failed to unpack RecipientsSet event"), nil
	}
	log.Info(fmt.Sprintf("Recipients set:%+v ", recipientsSetEvent))
	return nil, &recipientsSetEvent
}

func feeAccrued(data string) (error, *LogFeeAccrued) {
	var feeAccruedEvent LogFeeAccrued
	if err := decode[*LogFeeAccrued](bondingCurveABI, &feeAccruedEvent, "FeeAccrued", data); err != nil {
		return errors.Wrapf(err, "failed to unpack FeeAccrued event"), nil
	}
	log.Info(fmt.Sprintf("Fee accrued:%+v ", feeAccruedEvent))
	return nil, &feeAccruedEvent
}

func feeTransfer(data string) (error, *LogFeeTransfer) {
	var feeTransferEvent LogFeeTransfer
	if err := decode[*LogFeeTransfer](bondingCurveABI, &feeTransferEvent, "FeeTransfer", data); err != nil {
		return errors.Wrapf(err, "failed to unpack FeeTransfer event"), nil
	}
	log.Info(fmt.Sprintf("Fee transfer:%+v ", feeTransferEvent))
	return nil, &feeTransferEvent
}

func migrated(data string) (error, *LogMigrated) {
	var migratedEvent LogMigrated
	if err := decode[*LogMigrated](bondingCurveABI, &migratedEvent, "Migrated", data); err != nil {
		return errors.Wrapf(err, "failed to unpack Migrated event"), nil
	}
	log.Info(fmt.Sprintf("Migrated:%+v ", migratedEvent))
	return nil, &migratedEvent
}

func lpClaimed(data string) (error, *LogLPClaimed) {
	var lpClaimedEvent LogLPClaimed
	if err := decode[*LogLPClaimed](bondingCurveABI, &lpClaimedEvent, "LPClaimed", data); err != nil {
		return errors.Wrapf(err, "failed to unpack LPClaimed event"), nil
	}
	log.Info(fmt.Sprintf("LP claimed:%+v ", lpClaimedEvent))
	return nil, &lpClaimedEvent
}
