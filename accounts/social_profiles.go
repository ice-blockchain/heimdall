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
	username = strings.ToLower(username)
	result, err := storage.Get[any](ctx, a.db, `SELECT 1 FROM social_profiles WHERE username = $1 LIMIT 1`, username)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return errors.Wrapf(err, "failed to check username availability")
	}
	if result != nil {
		return errors.Wrapf(ErrDuplicate, "username %v already exists", username)
	}

	return nil
}

func (a *accounts) UpsertSocialProfile(ctx context.Context, userIDOrMasterKey, username, displayName, referralUsername, loggedInUserUserID string) (*SocialProfile, error) {
	dbUsr, err := a.getUserByID(ctx, userIDOrMasterKey)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userIDOrMasterKey)
	}
	if dbUsr == nil || dbUsr.ID != loggedInUserUserID {
		return nil, ErrUnauthorized
	}
	if username != "" && !isUsernameValid(username) {
		return nil, errors.Wrapf(ErrInvalidUsername, "username %v is invalid", username)
	}
	if username != "" {
		username = strings.ToLower(username)
	}
	lookupText := make([]string, 0, 2)
	if username != "" {
		lookupText = append(lookupText, username)
	}
	if displayName != "" && displayName != username {
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
		WITH resolved_keys AS (
			SELECT COALESCE((SELECT master_pubkey FROM users WHERE id = $1), $1) AS current_user_master_pubkey,
			       CASE WHEN $4 != '' THEN 
			           (SELECT master_pubkey FROM social_profiles WHERE username = $4 LIMIT 1)
			       ELSE NULL END AS referral_user_master_pubkey
		)
		MERGE INTO social_profiles AS target
		USING (
			SELECT 
				rk.current_user_master_pubkey AS master_pubkey,
				$2::TEXT AS username,
				$3::TIMESTAMP AS current_time,
				$5::TEXT AS display_name,
				$6::TEXT AS lookup,
				rk.referral_user_master_pubkey AS referral_master_pubkey,
				(SELECT username FROM social_profiles WHERE master_pubkey = rk.current_user_master_pubkey LIMIT 1) AS old_username
			FROM resolved_keys rk
			WHERE 
				($2 != '' OR (SELECT username FROM social_profiles WHERE master_pubkey = rk.current_user_master_pubkey LIMIT 1) IS NOT NULL)
				-- Block self-referral
				AND NOT ($4 != '' AND rk.referral_user_master_pubkey IS NOT NULL AND rk.referral_user_master_pubkey = rk.current_user_master_pubkey)
				-- Block direct circular referral: A->me->A
				AND NOT ($4 != '' AND rk.referral_user_master_pubkey IS NOT NULL AND EXISTS (
					SELECT 1 FROM social_profiles referral_user_profile 
					WHERE referral_user_profile.master_pubkey = rk.referral_user_master_pubkey
					AND referral_user_profile.referral_master_pubkey = rk.current_user_master_pubkey
				))
				-- Block 2-level circular referral: A->me->B->A
				AND NOT ($4 != '' AND rk.referral_user_master_pubkey IS NOT NULL AND EXISTS (
					SELECT 1 FROM social_profiles referral_user_profile 
					WHERE referral_user_profile.master_pubkey = rk.referral_user_master_pubkey
					AND referral_user_profile.referral_master_pubkey IS NOT NULL
					AND EXISTS (
						SELECT 1 FROM social_profiles intermediate_user_profile 
						WHERE intermediate_user_profile.master_pubkey = referral_user_profile.referral_master_pubkey 
						AND intermediate_user_profile.referral_master_pubkey = rk.current_user_master_pubkey
					)
				))
		) AS source
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
			target.master_pubkey, 
			target.username, 
			target.display_name, 
			target.referral_master_pubkey,
			COALESCE((SELECT referral_profile.username FROM social_profiles referral_profile WHERE referral_profile.master_pubkey = target.referral_master_pubkey), '') as referral_username,
			COALESCE(source.old_username, '') as old_username,
			NOT (source.old_username IS NOT NULL) as is_new_profile
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
			if referralUsername != "" {
				return nil, ErrWrongReferral
			}

			return nil, errors.Wrap(ErrInvalidUsername, "validation failed - operation was blocked")
		}

		return nil, errors.Wrapf(err, "failed to upsert social profile")
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

func (a *accounts) SearchSocialProfiles(ctx context.Context, tpe SearchType, keyword string, limit, offset uint64) ([]*LiteUser, error) {
	query := `SELECT sp.master_pubkey, COALESCE(u.ion_connect_relays, ARRAY[]::text[]) as ion_connect_relays
			FROM social_profiles sp
			JOIN users u ON sp.master_pubkey = u.master_pubkey`
	switch tpe {
	case SearchTypeStartsWith:
		query += ` WHERE sp.lookup &^ $1 `
	case SearchTypeContains:
		query += ` WHERE sp.lookup &@ $1 `
	}
	query += ` ORDER BY sp.master_pubkey LIMIT $2 OFFSET $3`
	args := []interface{}{strings.ToLower(keyword), limit, offset}
	profiles, err := storage.Select[LiteUser](ctx, a.db, query, args...)
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
				{"d", usernameProofOfOwnershipBadgeName + "~" + username},
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
				{"a", fmt.Sprintf("%d:%s:%s~%s", nostr.KindBadgeDefinition, publicKey, usernameProofOfOwnershipBadgeName, username)},
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
