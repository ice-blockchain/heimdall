// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ice-blockchain/wintr/log"
	"github.com/pkg/errors"
)

func (t *tokenAnalytics) processEvent(ctx context.Context, event *txEvent) error {
	switch event.Topic0 {
	case eventTokenCreated.Hex():
		return t.tokenCreated(ctx, event)
	case eventSwapped.Hex():
		return t.tokenSwapped(ctx, event)
	case eventPairRegistered.Hex():
		return t.pairRegistered(ctx, event)
	case eventBought.Hex():
		return t.tokenBought(ctx, event)
	case eventSold.Hex():
		return t.tokenSold(ctx, event)
	case eventRecipientsSet.Hex():
		return t.recipientsSet(ctx, event)
	case eventFeeAccrued.Hex():
		return t.feeAccrued(ctx, event)
	case eventFeeTransfer.Hex():
		return t.feeTransfer(ctx, event)
	case eventMigrated.Hex():
		return t.migrated(ctx, event)
	case eventLPClaimed.Hex():
		return t.lpClaimed(ctx, event)
	default:
		log.Warn(fmt.Sprintf("Unknown event: %v, params: %v", event.Topic0, event.Topics))
	}
	time.Sleep(time.Duration(rand.Int63n(10000)) * time.Millisecond)
	return nil
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

func (t *tokenAnalytics) tokenCreated(ctx context.Context, event *txEvent) error {
	var tokenCreatedEvent logTokenCreated
	if err := decode[*logTokenCreated](t.bondingCurveABI, &tokenCreatedEvent, "BondedTokenCreated", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack BondedTokenCreated event")
	}
	log.Info(fmt.Sprintf("Token created:%+v ", tokenCreatedEvent))
	if event.Address == t.cfg.BondingCurveContract {
		// TODO: create stream for user token (tokenCreatedEvent.Address)
		return nil
	}
	return nil
}

func (t *tokenAnalytics) pairRegistered(ctx context.Context, event *txEvent) error {
	var pairRegisteredEvent logPairRegistered
	if err := decode[*logPairRegistered](t.bondingCurveABI, &pairRegisteredEvent, "PairRegistered", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack PairRegistered event")
	}
	log.Info(fmt.Sprintf("Pair registered:%+v ", pairRegisteredEvent))
	return nil
}

func (t *tokenAnalytics) tokenSwapped(ctx context.Context, event *txEvent) error {
	var tokenSwappedEvent logTokenSwapped
	if err := decode[*logTokenSwapped](t.bondingCurveABI, &tokenSwappedEvent, "Swapped", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack Swapped event")
	}
	log.Info(fmt.Sprintf("Token swapped:%+v ", tokenSwappedEvent))
	return nil
}

func (t *tokenAnalytics) tokenBought(ctx context.Context, event *txEvent) error {
	var tokenBoughtEvent logTokenBought
	if err := decode[*logTokenBought](t.bondingCurveABI, &tokenBoughtEvent, "Bought", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack Bought event")
	}
	log.Info(fmt.Sprintf("Token bought:%+v ", tokenBoughtEvent))
	return nil
}

func (t *tokenAnalytics) tokenSold(ctx context.Context, event *txEvent) error {
	var tokenSoldEvent logTokenSold
	if err := decode[*logTokenSold](t.bondingCurveABI, &tokenSoldEvent, "Sold", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack Sold event")
	}
	log.Info(fmt.Sprintf("Token sold:%+v ", tokenSoldEvent))
	return nil
}

func (t *tokenAnalytics) recipientsSet(ctx context.Context, event *txEvent) error {
	var recipientsSetEvent logRecipientsSet
	if err := decode[*logRecipientsSet](t.bondingCurveABI, &recipientsSetEvent, "RecipientsSet", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack RecipientsSet event")
	}
	log.Info(fmt.Sprintf("Recipients set:%+v ", recipientsSetEvent))
	return nil
}

func (t *tokenAnalytics) feeAccrued(ctx context.Context, event *txEvent) error {
	var feeAccruedEvent logFeeAccrued
	if err := decode[*logFeeAccrued](t.bondingCurveABI, &feeAccruedEvent, "FeeAccrued", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack FeeAccrued event")
	}
	log.Info(fmt.Sprintf("Fee accrued:%+v ", feeAccruedEvent))
	return nil
}

func (t *tokenAnalytics) feeTransfer(ctx context.Context, event *txEvent) error {
	var feeTransferEvent logFeeTransfer
	if err := decode[*logFeeTransfer](t.bondingCurveABI, &feeTransferEvent, "FeeTransfer", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack FeeTransfer event")
	}
	log.Info(fmt.Sprintf("Fee transfer:%+v ", feeTransferEvent))
	return nil
}

func (t *tokenAnalytics) migrated(ctx context.Context, event *txEvent) error {
	var migratedEvent logMigrated
	if err := decode[*logMigrated](t.bondingCurveABI, &migratedEvent, "Migrated", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack Migrated event")
	}
	log.Info(fmt.Sprintf("Migrated:%+v ", migratedEvent))
	return nil
}

func (t *tokenAnalytics) lpClaimed(ctx context.Context, event *txEvent) error {
	var lpClaimedEvent logLPClaimed
	if err := decode[*logLPClaimed](t.bondingCurveABI, &lpClaimedEvent, "LPClaimed", event.Data); err != nil {
		return errors.Wrapf(err, "failed to unpack LPClaimed event")
	}
	log.Info(fmt.Sprintf("LP claimed:%+v ", lpClaimedEvent))
	return nil
}
