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
	var (
		profile              *socialProfile
		proofEvents          []*model.Event
		referralMasterPubKey = masterPubkey
		changeUsernameFlow   bool
	)
	existingProfile, err := a.getSocialProfileByMasterPubkey(ctx, masterPubkey)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to get social profile for master pubkey %v", masterPubkey)
	}
	changeUsernameFlow = existingProfile == nil || (username != "" && username != existingProfile.Username)
	if changeUsernameFlow {
		if err = a.VerifyUsernameAvailability(ctx, username); err != nil {
			return nil, errors.Wrapf(err, "failed to verify username availability for username %v", username)
		}
	}
	if referralUsername != "" {
		referralProfile, err := a.getSocialProfileByUsername(ctx, referralUsername)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get referral user by username %v", referralUsername)
		}
		if referralProfile != nil {
			referralMasterPubKey = referralProfile.MasterPubkey
		}
	}
	if existingProfile != nil {
		if profile, err = a.updateSocialProfile(ctx, existingProfile, username, displayName, referralMasterPubKey); err != nil {
			return nil, errors.Wrapf(err, "failed to update social profile for master pubkey %v", masterPubkey)
		}
	} else {
		if profile, err = a.insertSocialProfile(ctx, masterPubkey, username, displayName, referralMasterPubKey); err != nil {
			return nil, errors.Wrapf(err, "failed to insert social profile for master pubkey %v", masterPubkey)
		}
	}
	if changeUsernameFlow {
		proofEvents, err = a.generateUsernameProofEvents(masterPubkey, profile.Username)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to generate username proof events for master pubkey %v", masterPubkey)
		}
	}

	return &SocialProfile{
		Username:      profile.Username,
		DisplayName:   profile.DisplayName,
		Referral:      referralUsername,
		UsernameProof: proofEvents,
	}, nil
}

func (a *accounts) getSocialProfileByMasterPubkey(ctx context.Context, masterPubkey string) (*socialProfile, error) {
	profile, err := storage.Get[socialProfile](ctx, a.db, `
		SELECT created_at, updated_at, master_pubkey, username, display_name, referral_master_pubkey
		FROM social_profiles
		WHERE master_pubkey = $1`, masterPubkey)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to get social profile for master pubkey %v", masterPubkey)
	}

	return profile, nil
}

func (a *accounts) getSocialProfileByUsername(ctx context.Context, username string) (*socialProfile, error) {
	profile, err := storage.Get[socialProfile](ctx, a.db, `
		SELECT created_at, updated_at, master_pubkey, username, display_name, referral_master_pubkey
		FROM social_profiles
		WHERE username = $1`, username)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to get social profile for username %v", username)
	}

	return profile, nil
}

func (a *accounts) updateSocialProfile(ctx context.Context, existingProfile *socialProfile, username, displayName, referralMasterPubkey string) (*socialProfile, error) {
	now := time.Now()
	updateFields := make([]string, 0, 4)
	args := []interface{}{now.Time, existingProfile.MasterPubkey}
	argIndex := 3
	needUpdateLookup := false
	if username != "" && username != existingProfile.Username {
		updateFields = append(updateFields, fmt.Sprintf("username = $%d", argIndex))
		args = append(args, username)
		argIndex++
		needUpdateLookup = true
	}
	if displayName != "" && displayName != existingProfile.DisplayName {
		updateFields = append(updateFields, fmt.Sprintf("display_name = $%d", argIndex))
		args = append(args, displayName)
		argIndex++
		needUpdateLookup = true
	}
	if referralMasterPubkey != "" && referralMasterPubkey != existingProfile.ReferralMasterPubkey {
		updateFields = append(updateFields, fmt.Sprintf("referral_master_pubkey = $%d", argIndex))
		args = append(args, referralMasterPubkey)
		argIndex++
	}
	if needUpdateLookup {
		lookupText := make([]string, 0, 2)
		if username != "" {
			lookupText = append(lookupText, username)
		}
		if displayName != "" {
			lookupText = append(lookupText, displayName)
		}
		if len(lookupText) > 0 {
			updateFields = append(updateFields, fmt.Sprintf("lookup = to_tsvector('english', $%d)", argIndex))
			args = append(args, lookup(strings.Join(lookupText, " ")))
			argIndex++
		}
	}
	if len(updateFields) > 0 {
		query := fmt.Sprintf(`UPDATE social_profiles
									 SET updated_at = $1, 
									 	%s 
									 WHERE master_pubkey = $2
									 RETURNING created_at, updated_at, master_pubkey, username, display_name`, strings.Join(updateFields, ", "))
		updatedProfile, err := storage.ExecOne[socialProfile](ctx, a.db, query, args...)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to update social profile")
		}

		return updatedProfile, nil
	}

	return existingProfile, nil
}

func (a *accounts) insertSocialProfile(ctx context.Context, masterPubkey, username, displayName, referralMasterPubkey string) (*socialProfile, error) {
	now := time.Now()
	lookupText := make([]string, 0, 2)
	if username != "" {
		lookupText = append(lookupText, username)
	}
	if displayName != "" {
		lookupText = append(lookupText, displayName)
	}
	stmt := `INSERT INTO social_profiles (
				created_at, updated_at, master_pubkey, username, display_name, referral_master_pubkey, lookup
			) VALUES (
				$1, $1, $2, $3, $4, $5, to_tsvector('english', $6)
			) RETURNING created_at, updated_at, master_pubkey, username, display_name`
	args := []interface{}{now.Time, masterPubkey, username, displayName, referralMasterPubkey, lookup(strings.Join(lookupText, " "))}

	profile, err := storage.ExecOne[socialProfile](ctx, a.db, stmt, args...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create social profile")
	}

	return profile, nil
}

func (a *accounts) SearchSocialProfiles(ctx context.Context, keyword string, limit uint64) ([]*LiteUser, error) {
	profiles, err := storage.Select[LiteUser](ctx, a.db, `
		SELECT sp.master_pubkey, COALESCE(u.ion_connect_relays, ARRAY[]::text[]) as ion_connect_relays
		FROM social_profiles sp
		JOIN users u
		ON sp.master_pubkey = u.master_pubkey
		WHERE sp.lookup @@ $1::tsquery
		LIMIT $2`, keyword, limit)
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

func lookup(username string) string {
	return strings.ToLower(strings.Join(generateUsernameKeywords(username), " "))
}

func generateUsernameKeywords(username string) []string {
	if username == "" {
		return nil
	}
	keywordsMap := make(map[string]struct{})
	for _, part := range append(strings.Split(username, "."), username) {
		for i := range len(part) {
			keywordsMap[part[:i+1]] = struct{}{}
			keywordsMap[part[len(part)-1-i:]] = struct{}{}
		}
	}
	keywords := make([]string, 0, len(keywordsMap))
	for keyword := range keywordsMap {
		keywords = append(keywords, keyword)
	}

	return keywords
}
