// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	deviceidentification "github.com/ice-blockchain/heimdall/accounts/internal/device-identification"
	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) validateRequestIDAndExtractVisitor(ctx context.Context, now *time.Time, requestID string) (visitorID, devicePubkey string, err error) {
	visitorID, devicePubkey, err = a.deviceIdentificationClient.ValidateRequestID(ctx, now.Time, requestID, clientIPAddress(ctx))
	if err != nil {
		if errors.Is(err, deviceidentification.ErrUnknownDevice) {
			log.Error(err)
			return "", "", &dfns.DfnsInternalError{
				Message:    deviceidentification.ErrUnknownDevice.Error(),
				HTTPStatus: http.StatusForbidden,
			}
		}
		return "", "", errors.Wrapf(err, "failed to validate visitor id")
	}
	return visitorID, devicePubkey, nil
}

func (a *accounts) masterKeyExists(ctx context.Context, masterPubKey string) error {
	_, err := a.getUserByID(ctx, masterPubKey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			err = deviceidentification.ErrUnknownDevice
		}
		return errors.Wrapf(err, "failed to check user existence by master key %v", masterPubKey)
	}

	return nil
}

func (a *accounts) generateDeviceVerifiedBadges(devicePubkey string) ([]*model.Event, error) {
	publicKey, err := model.GetPublicKey(a.privateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key")
	}
	badgeDefinitionEvent := model.Event{
		Event: nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      nostr.KindBadgeDefinition,
			Tags: model.Tags{
				{"d", deviceIdentificationProofBadgeName + "~" + devicePubkey},
				{"name", "Device Identified and Verified by ION Identity"},
				{"description", "Awarded by ION Identity to each user's device that is verified to be a valid device of that user"},
				identifiedDeviceBadgeThumbnail256X256Tag,
				identifiedDeviceImage1024X1024Tag,
			},
		},
	}
	if err := badgeDefinitionEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrapf(err, "failed to sign badge definition event")
	}
	badgeAwardEvent := model.Event{
		Event: nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      nostr.KindBadgeAward,
			Tags: model.Tags{
				{"a", fmt.Sprintf("%d:%s:%s~%s", nostr.KindBadgeDefinition, publicKey, deviceIdentificationProofBadgeName, devicePubkey)},
				{"p", devicePubkey},
			},
		},
	}
	if err := badgeAwardEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrapf(err, "failed to sign badge award event")
	}

	return []*model.Event{&badgeDefinitionEvent, &badgeAwardEvent}, nil
}
func (a *accounts) DeviceIdentificationProofs(ctx context.Context, attestationEvent *model.Event, devicePubkey string) (proofs []*model.Event, err error) {
	now := nostr.Now()
	var allowed bool
	allowed, err = model.OnBehalfIsAccessAllowed(attestationEvent.Tags, devicePubkey, 0, now)
	if err != nil {
		return nil, errors.Wrapf(ErrNotFound, "failed to parse attestation event: %v", err)
	}
	if !allowed {
		return nil, errors.Wrapf(ErrNotFound, "device is not allowed in attestation")
	}
	if err = a.validateDevice(ctx, attestationEvent.GetMasterPublicKey(), devicePubkey); err != nil {
		return nil, errors.Wrapf(err, "failed to verify device pubkey in db %v", devicePubkey)
	}
	return a.generateDeviceVerifiedBadges(devicePubkey)
}

func (a *accounts) validateDevice(ctx context.Context, masterKey string, devicePubkey string) error {
	usr, err := a.getUserByID(ctx, masterKey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return errors.Wrapf(ErrNotFound, "user %v not found", masterKey)
		}
		return errors.Wrapf(err, "failed get user %v for device check", masterKey)
	}
	if usr.ID != server.LoggedInUser(ctx).UserID() {
		return errors.Wrapf(ErrUnauthorized, "user auth mismatch")
	}
	validDevice, err := storage.Get[struct {
		ValidDevice bool `db:"valid_device"`
	}](ctx, a.db, `SELECT exists(SELECT 1 FROM users_visitors 
						 WHERE  user_id = $1 AND device_pubkey = $2) as valid_device;`, usr.ID, devicePubkey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return errors.Wrapf(ErrNotFound, "device %v not found for usr %v (%v)", devicePubkey, usr.ID, masterKey)
		}
		return errors.Wrapf(err, "failed to check if device %v for user %v is valid", devicePubkey, masterKey)
	}
	if !validDevice.ValidDevice {
		return errors.Wrapf(ErrNotFound, "device %v not valid for usr %v (%v)", devicePubkey, usr.ID, masterKey)
	}
	return nil
}
