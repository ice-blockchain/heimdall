// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) VerifyUsernameAvailability(ctx context.Context, username string) error {
	if !isUsernameValid(username) {
		return errors.Wrapf(ErrInvalidUsername, "username %v is invalid", username)
	}
	result, err := storage.Get[any](ctx, a.db, `SELECT 1 FROM social_profiles WHERE username = $1 LIMIT 1`, username)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return errors.Wrapf(err, "failed to check username availability")
	}
	if result != nil {
		return errors.Wrapf(ErrDuplicate, "username %v already exists", username)
	}

	return nil
}

func (a *accounts) UpsertSocialProfile(ctx context.Context, masterPubkey, username, displayName, referralUsername string) (*SocialProfile, error) {
	if username != "" && !isUsernameValid(username) {
		return nil, errors.Wrapf(ErrInvalidUsername, "username %v is invalid", username)
	}
	var result *SocialProfile
	if err := storage.DoInTransaction(ctx, a.db, func(tx storage.QueryExecer) error {
		existingProfile, err := storage.Get[socialProfile](ctx, tx, `SELECT username FROM social_profiles WHERE master_pubkey = $1`, masterPubkey)
		if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
			return errors.Wrapf(err, "failed to get profile info")
		}
		if existingProfile == nil && username == "" {
			return errors.Wrap(ErrInvalidUsername, "username cannot be empty when creating a new profile")
		}
		lookupText := make([]string, 0, 2)
		if username != "" {
			lookupText = append(lookupText, username)
		}
		if displayName != "" {
			lookupText = append(lookupText, displayName)
		}
		lookupValue := strings.ToLower(strings.Join(lookupText, " "))
		args := []interface{}{
			masterPubkey,
			username,
			time.Now(),
			referralUsername,
			displayName,
			lookupValue,
		}
		query := `
			MERGE INTO social_profiles AS target
			USING (
				SELECT 
					$1::TEXT as master_pubkey, 
					$2::TEXT as username,
					CASE WHEN $4 != '' THEN 
						(SELECT master_pubkey FROM social_profiles WHERE username = $4 LIMIT 1)
					ELSE NULL END as referral_master_pubkey
			) AS source
			ON target.master_pubkey = source.master_pubkey
			WHEN MATCHED THEN
				UPDATE SET 
					updated_at = $3,
					username = CASE WHEN $2 != '' THEN $2 ELSE target.username END,
					display_name = CASE WHEN $5 != '' THEN $5 ELSE target.display_name END,
					referral_master_pubkey = CASE 
						WHEN source.referral_master_pubkey IS NOT NULL THEN source.referral_master_pubkey
						ELSE target.referral_master_pubkey 
					END,
					lookup = CASE 
						WHEN ($2 != '' AND target.username != $2) OR ($5 != '' AND target.display_name != $5)
						THEN $6 
						ELSE target.lookup 
					END
			WHEN NOT MATCHED THEN
				INSERT (created_at, updated_at, master_pubkey, username, display_name, referral_master_pubkey, lookup)
				VALUES (
					$3, $3, $1, $2, $5, 
					COALESCE(source.referral_master_pubkey, $1), 
					$6
				)
			RETURNING 
				target.created_at, target.updated_at, target.master_pubkey, target.username, target.display_name, target.referral_master_pubkey,
				$4 as referral_username
		`
		type resultProfile struct {
			socialProfile
			ReferralUsername string `db:"referral_username"`
		}
		profile, err := storage.ExecOne[resultProfile](ctx, tx, query, args...)
		if err != nil {
			return errors.Wrapf(err, "failed to upsert social profile with MERGE")
		}

		var proofEvents []*model.Event
		if existingProfile == nil || username != "" && existingProfile.Username != username {
			var eventErr error
			proofEvents, eventErr = a.generateUsernameProofEvents(masterPubkey, profile.Username)
			if eventErr != nil {
				return errors.Wrapf(eventErr, "failed to generate username proof events for master pubkey %v", masterPubkey)
			}
		}
		result = &SocialProfile{
			Username:      profile.Username,
			DisplayName:   profile.DisplayName,
			Referral:      profile.ReferralUsername,
			UsernameProof: proofEvents,
		}

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "failed to upsert social profile")
	}

	return result, nil
}

func (a *accounts) SearchSocialProfiles(ctx context.Context, tpe SearchType, keyword string, limit uint64) ([]*LiteUser, error) {
	query := `
		SELECT sp.master_pubkey, COALESCE(u.ion_connect_relays, ARRAY[]::text[]) as ion_connect_relays
		FROM social_profiles sp
		JOIN users u ON sp.master_pubkey = u.master_pubkey
		WHERE sp.lookup ILIKE $1
		LIMIT $2`

	likePattern := keyword
	switch tpe {
	case SearchTypeStartsWith:
		likePattern = keyword + "%"
	case SearchTypeContains:
		likePattern = "%" + keyword + "%"
	}
	profiles, err := storage.Select[LiteUser](ctx, a.db, query, likePattern, limit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to search user profiles")
	}
	if len(profiles) == 0 {
		return []*LiteUser{}, nil
	}

	return profiles, nil
}

func (a *accounts) generateUsernameProofEvents(masterPubkey, username string) ([]*model.Event, error) {
	publicKey, err := model.GetPublicKey(a.privateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key")
	}
	badgeDefinitionEvent := model.Event{
		Event: nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      nostr.KindBadgeDefinition,
			Tags: model.Tags{
				{"d", usernameProofOfOwnershipBadgeName + ":" + username},
				{"name", "username proof of ownership for " + username + " from ION Identity"},
				{"description", "Awarded by ION Identity to the user that owns the " + username + " username"},
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
				{"a", fmt.Sprintf("%d:%s:%s:%s", nostr.KindBadgeDefinition, publicKey, usernameProofOfOwnershipBadgeName, username)},
				{"p", masterPubkey},
			},
		},
	}
	if err := badgeAwardEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrapf(err, "failed to sign badge award event")
	}

	return []*model.Event{&badgeDefinitionEvent, &badgeAwardEvent}, nil
}

func isUsernameValid(username string) bool {
	return usernameRegex.MatchString(username)
}
