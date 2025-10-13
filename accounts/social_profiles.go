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
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) VerifyUsernameAvailability(ctx context.Context, username, loggedInUserID string) error {
	if !isUsernameValid(username) {
		return errors.Wrapf(ErrInvalidUsername, "username %v is invalid", username)
	}
	username = strings.ToLower(username)
	type row struct {
		ID           string `db:"id"`
		MasterPubkey string `db:"master_pubkey"`
	}
	r, err := storage.Get[row](ctx, a.db, `SELECT u.id, sp.master_pubkey 
									FROM social_profiles sp
									JOIN users u ON sp.master_pubkey = u.master_pubkey 
									WHERE sp.username = $1 LIMIT 1`, username)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return errors.Wrapf(err, "failed to check username availability")
	}
	if r == nil {
		return nil
	}
	if r.ID == r.MasterPubkey && strings.HasPrefix(r.MasterPubkey, "reserved_") {
		return errors.Wrap(ErrReserved, "username is reserved")
	}
	if r.ID == loggedInUserID {
		return nil
	}

	return errors.Wrapf(ErrDuplicate, "username %v already exists", username)
}

func (a *accounts) UpsertSocialProfile(ctx context.Context, userIDOrMasterKey, username, displayName, referralUsername, bio, avatar, loggedInUserUserID string) (*SocialProfile, error) {
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

	args := []interface{}{
		userIDOrMasterKey,
		username,
		time.Now(),
		referralUsername,
		displayName,
		bio,
		avatar,
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
				rk.referral_user_master_pubkey AS referral_master_pubkey,
				$6::TEXT AS bio,
				$7::TEXT AS avatar
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
				lookup = LOWER(TRIM(
					CASE 
						WHEN source.username != '' THEN source.username 
						ELSE (SELECT username FROM social_profiles WHERE master_pubkey = source.master_pubkey LIMIT 1)
					END ||
					' ' ||
					CASE 
						WHEN source.display_name != '' THEN source.display_name 
						ELSE (SELECT display_name FROM social_profiles WHERE master_pubkey = source.master_pubkey LIMIT 1)
					END
				)),
				bio = CASE WHEN source.bio != '' THEN source.bio ELSE target.bio END,
				avatar = CASE WHEN source.avatar != '' THEN source.avatar ELSE target.avatar END
		WHEN NOT MATCHED AND source.username != '' THEN
			INSERT (created_at, updated_at, master_pubkey, username, display_name, referral_master_pubkey, lookup, bio, avatar)
			VALUES (
				source.current_time, 
				source.current_time, 
				source.master_pubkey, 
				source.username, 
				source.display_name, 
				source.referral_master_pubkey, 
				LOWER(TRIM(COALESCE(source.username, '') || ' ' || COALESCE(source.display_name, ''))),
				source.bio,
				source.avatar
			)
		RETURNING 
			target.created_at, 
			target.updated_at, 
			target.master_pubkey, 
			target.username, 
			target.display_name, 
			target.referral_master_pubkey,
			COALESCE((SELECT referral_profile.username FROM social_profiles referral_profile WHERE referral_profile.master_pubkey = target.referral_master_pubkey), '') as referral_username,
			target.bio,
			target.avatar,
			target.referral_count
	`
	type resultProfile struct {
		socialProfile
		ReferralUsername string `db:"referral_username"`
	}
	profile, err := storage.ExecOne[resultProfile](ctx, a.db, query, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			if referralUsername != "" {
				return nil, ErrWrongReferral
			}

			return nil, errors.Wrap(ErrInvalidUsername, "validation failed - operation was blocked")
		}
		if storage.IsErr(err, storage.ErrDuplicate) {
			type reserved struct {
				ID           string `db:"id"`
				MasterPubkey string `db:"master_pubkey"`
			}
			row, gErr := storage.Get[reserved](ctx, a.db, `SELECT u.id, sp.master_pubkey 
													  FROM social_profiles sp
													  JOIN users u
													  ON sp.master_pubkey = u.master_pubkey
													  WHERE username = $1 LIMIT 1`, username)
			if gErr != nil {
				return nil, errors.Wrapf(gErr, "failed to get owner of conflicting username")
			}
			if row.ID == row.MasterPubkey && strings.HasPrefix(row.MasterPubkey, "reserved_") {
				return nil, errors.Wrap(ErrReserved, "username is reserved")
			}

			return nil, errors.Wrap(ErrDuplicate, "username is already taken")
		}

		return nil, errors.Wrapf(err, "failed to upsert social profile")
	}

	proofEvents, err := a.generateUsernameProofEvents(profile.MasterPubkey, profile.Username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate username proof events for master pubkey %v", profile.MasterPubkey)
	}
	result := &SocialProfile{
		Username:          profile.Username,
		DisplayName:       profile.DisplayName,
		Referral:          profile.ReferralUsername,
		ReferralMasterKey: profile.ReferralMasterPubkey,
		UsernameProof:     proofEvents,
		Bio:               profile.Bio,
		Avatar:            profile.Avatar,
		ReferralCount:     profile.ReferralCount,
	}

	return result, nil
}

func (a *accounts) GetSocialProfile(ctx context.Context, userIDOrMasterKey string) (*SocialProfile, error) {
	dbUsr, err := a.getUserByID(ctx, userIDOrMasterKey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userIDOrMasterKey)
	}
	type resultProfile struct {
		socialProfile
		ReferralUsername string `db:"referral_username"`
	}
	profile, err := storage.Get[resultProfile](ctx, a.db, `SELECT 
        social_profiles.created_at, 
		social_profiles.updated_at, 
		social_profiles.master_pubkey, 
		social_profiles.username, 
		social_profiles.display_name, 
		social_profiles.referral_master_pubkey,
		social_profiles.bio,
		social_profiles.avatar,
		social_profiles.referral_count,
        COALESCE((SELECT referral_profile.username FROM social_profiles referral_profile WHERE referral_profile.master_pubkey = social_profiles.referral_master_pubkey), '') as referral_username
       FROM social_profiles WHERE master_pubkey = $1 LIMIT 1`, dbUsr.MasterPubKey)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, errors.Wrapf(err, "failed to get social profile")
	}
	res := &SocialProfile{
		Username:      profile.Username,
		DisplayName:   profile.DisplayName,
		Bio:           profile.Bio,
		Avatar:        profile.Avatar,
		ReferralCount: profile.ReferralCount,
	}
	if server.LoggedInUser(ctx) != nil && ((dbUsr != nil && dbUsr.ID == server.LoggedInUser(ctx).UserID()) || userIDOrMasterKey == server.LoggedInUser(ctx).UserID()) {
		res.Referral = profile.ReferralUsername
		res.ReferralMasterKey = profile.ReferralMasterPubkey
		res.ReferralCount = profile.ReferralCount
	}

	return res, nil
}

func (a *accounts) SearchSocialProfiles(ctx context.Context, tpe SearchType, keyword, followedBy, followerOf string, limit, offset uint64) ([]*LiteUser, error) {
	kw := strings.ToLower(keyword)

	const fixedPre = uint64(200)
	pre := fixedPre
	if offset > pre {
		log.Info(fmt.Sprintf("search-social-profiles: offset %d exceeds pre-limit %d", offset, pre))
	}

	var args []interface{}
	argIdx := 1
	var joinClause string
	if followedBy != "" {
		args = append(args, followedBy)
		joinClause = ` JOIN following f ON f.follower_master_pubkey = $1 AND f.master_pubkey = r.master_pubkey
					   JOIN users u ON f.master_pubkey = u.master_pubkey`
		argIdx++
	} else if followerOf != "" {
		args = append(args, followerOf)
		joinClause = ` JOIN following f ON f.master_pubkey = $1 AND f.follower_master_pubkey = r.master_pubkey
					   JOIN users u ON f.follower_master_pubkey = u.master_pubkey`
		argIdx++
	} else {
		joinClause = ` JOIN users u ON u.master_pubkey = r.master_pubkey`
	}

	kwIdx := argIdx
	if tpe == SearchTypeContains {
		args = append(args, kw)
	} else {
		args = append(args, kw+"%")
	}
	argIdx++
	preIdx := argIdx
	args = append(args, int(pre))
	argIdx++
	limitIdx := argIdx
	args = append(args, limit)
	argIdx++
	offsetIdx := argIdx
	args = append(args, offset)

	var whereClause string
	if tpe == SearchTypeContains {
		whereClause = fmt.Sprintf(` WHERE sp.lookup %% $%d AND similarity(sp.lookup, $%d) >= 0.3`, kwIdx, kwIdx)
	} else {
		whereClause = fmt.Sprintf(` WHERE sp.lookup LIKE $%d AND similarity(sp.lookup, $%d) >= 0.3`, kwIdx, kwIdx)
	}

	query := fmt.Sprintf(`
		WITH candidates AS (
			SELECT sp.master_pubkey, sp.lookup, u.verified, similarity(sp.lookup, $%d) AS sim,
			username, display_name, avatar
			FROM social_profiles sp
			JOIN users u ON u.master_pubkey = sp.master_pubkey
			%s
			ORDER BY sp.lookup <-> $%d, sp.master_pubkey ASC
			LIMIT $%d
		),
		ranked AS (
			SELECT master_pubkey, lookup, sim, verified, username, display_name, avatar
			FROM candidates
			ORDER BY verified DESC, sim DESC, lookup ASC, master_pubkey ASC
			LIMIT $%d OFFSET $%d
		)
		SELECT r.master_pubkey, username, display_name, avatar,
			   (SELECT json_agg(x) FROM (SELECT url, relay_type as "type" FROM ion_connect_relays WHERE url=ANY(u.ion_connect_relays)) x) AS ion_connect_relays
		FROM ranked r
		%s`, kwIdx, whereClause, kwIdx, preIdx, limitIdx, offsetIdx, joinClause)

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
				{"name", "username proof of ownership for " + username + " from ION Identity (identity.io)"},
				{"description", "Awarded by ION Identity (identity.io) to the user that owns the " + username + " username"},
				{"p", masterPubkey},
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
