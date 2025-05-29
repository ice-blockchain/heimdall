// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
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

func (a *accounts) UpsertSocialProfile(ctx context.Context, userIDOrMasterKey, username, displayName, referralUsername string) (*SocialProfile, error) {
	dbUsr, err := a.getUserByID(ctx, userIDOrMasterKey)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userIDOrMasterKey)
	}
	loggedInUser := server.LoggedInUser(ctx)
	if dbUsr == nil || loggedInUser == nil || dbUsr.ID != loggedInUser.UserID() {
		return nil, ErrUnauthorized
	}
	if username != "" && !isUsernameValid(username) {
		return nil, errors.Wrapf(ErrInvalidUsername, "username %v is invalid", username)
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
		userIDOrMasterKey,
		username,
		time.Now(),
		referralUsername,
		displayName,
		lookupValue,
	}

	query := `
		WITH upsert_data AS (
			SELECT 
				COALESCE((SELECT master_pubkey FROM users WHERE id = $1), $1) AS master_pubkey,
				$2::TEXT AS username,
				$3::TIMESTAMP AS current_time,
				$5::TEXT AS display_name,
				$6::TEXT AS lookup,
				CASE WHEN $4 != '' THEN 
					(SELECT master_pubkey FROM social_profiles WHERE username = $4 LIMIT 1)
				ELSE NULL END AS referral_master_pubkey,
				(SELECT username FROM social_profiles WHERE master_pubkey = COALESCE(
					(SELECT master_pubkey FROM users WHERE id = $1), $1
				) LIMIT 1) AS old_username
		)
		MERGE INTO social_profiles AS target
		USING upsert_data AS source
		ON target.master_pubkey = source.master_pubkey
		WHEN MATCHED THEN
			UPDATE SET 
				updated_at = source.current_time,
				username = CASE WHEN source.username != '' THEN source.username ELSE target.username END,
				display_name = CASE WHEN source.display_name != '' THEN source.display_name ELSE target.display_name END,
				referral_master_pubkey = CASE 
					WHEN source.referral_master_pubkey IS NOT NULL THEN source.referral_master_pubkey
					ELSE target.referral_master_pubkey 
				END,
				lookup = CASE 
					WHEN (source.username != '' AND COALESCE(target.username, '') != source.username) 
					     OR (source.display_name != '' AND COALESCE(target.display_name, '') != source.display_name)
					THEN source.lookup
					ELSE target.lookup 
				END
		WHEN NOT MATCHED AND source.username != '' THEN
			INSERT (created_at, updated_at, master_pubkey, username, display_name, referral_master_pubkey, lookup)
			VALUES (
				source.current_time, 
				source.current_time, 
				source.master_pubkey, 
				source.username, 
				source.display_name, 
				source.referral_master_pubkey, 
				source.lookup
			)
		RETURNING 
			target.created_at, 
			target.updated_at, 
			(SELECT master_pubkey FROM upsert_data) as master_pubkey, 
			target.username, 
			target.display_name, 
			target.referral_master_pubkey,
			$4 as referral_username,
			(SELECT COALESCE(old_username, '') FROM upsert_data) as old_username,
			NOT (SELECT old_username IS NOT NULL FROM upsert_data) as is_new_profile
	`
	type resultProfile struct {
		socialProfile
		ReferralUsername string  `db:"referral_username"`
		OldUsername      *string `db:"old_username"`
		IsNewProfile     bool    `db:"is_new_profile"`
	}
	profile, err := storage.ExecOne[resultProfile](ctx, a.db, query, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, errors.Wrap(ErrInvalidUsername, "username cannot be empty when creating a new profile")
		}
		return nil, errors.Wrapf(err, "failed to upsert social profile with")
	}
	var proofEvents []*model.Event
	oldUsername := ""
	if profile.OldUsername != nil {
		oldUsername = *profile.OldUsername
	}
	if profile.IsNewProfile || (username != "" && oldUsername != username) {
		proofEvents, err = a.generateUsernameProofEvents(profile.MasterPubkey, profile.Username)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to generate username proof events for master pubkey %v", profile.MasterPubkey)
		}
	}
	result := &SocialProfile{
		Username:      profile.Username,
		DisplayName:   profile.DisplayName,
		Referral:      profile.ReferralUsername,
		UsernameProof: proofEvents,
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
