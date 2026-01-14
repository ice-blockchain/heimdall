// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
	"github.com/nbd-wtf/go-nostr"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/terror"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) getUserByID(ctx context.Context, userID string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT 
    created_at ,
    updated_at,
    id,                           
    identity_key_name,
    duplicate_of,
    master_pubkey,
    clients,
    email,
    phone_number,
    totp_authenticator_secret,
    (SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(users.ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x) AS ion_connect_relays,
    active_2fa_email,
    active_2fa_phone_number,
    active_2fa_totp_authenticator,
    verified
    FROM users where id = $1 or master_pubkey = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by ID %v", userID)
	}

	return u, nil
}

func (a *accounts) getUserByIdentityKeyName(ctx context.Context, identityKeyName string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT 
		created_at,
		updated_at,
		id,                           
		identity_key_name,
		duplicate_of,
		master_pubkey,
		clients,
		email,
		phone_number,
		totp_authenticator_secret,
		(SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(users.ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x) AS ion_connect_relays,
		active_2fa_email,
		active_2fa_phone_number,
		active_2fa_totp_authenticator,
		verified     
    FROM users where identity_key_name = $1`, identityKeyName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by identity key name %v", identityKeyName)
	}

	return u, nil
}

func clientIPAddress(ctx context.Context) string {
	return ctx.Value(clientIPCtxValueKey).(string)
}

func (a *accounts) GetOrAssignIONConnectRelays(ctx context.Context, userID string, followees []string) (relays []*UserAssignedRelay, err error) {
	usr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to check if user already have ion relays")
	}
	if len(usr.IONConnectRelays) > 0 {
		for i := range usr.IONConnectRelays {
			enhanceRelayURL(usr.IONConnectRelays[i])
		}
		return usr.IONConnectRelays, nil
	}
	if err = a.validateFollowees(ctx, followees); err != nil {
		return nil, errors.Wrapf(err, "failed to validate followees pubkeys")
	}

	return a.fetchAndUpdateRelays(ctx, userID, followees)
}

func (a *accounts) GetIONConnectIndexerRelays(ctx context.Context, userID string) (indexers []string, err error) {
	return a.fetchIONIndexers(ctx, userID)
}

func (a *accounts) GetContentCreators(ctx context.Context, limit uint64, excludeMasterPubKeys []string) ([]*LiteUser, error) {
	excludeClause := ""
	args := []any{}
	if len(excludeMasterPubKeys) > 0 {
		args = append(args, excludeMasterPubKeys)
		excludeClause = "WHERE NOT master_pubkey = ANY($1)"
	}
	args = append(args, limit)
	query := `SELECT x.master_pubkey,  s.username, s.display_name, s.avatar,
       		  (SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(u.ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x) AS ion_connect_relays
			  FROM (SELECT master_pubkey FROM content_creators ` + excludeClause + ` 
			  ORDER BY random() LIMIT $` + strconv.Itoa(len(args)) + `) x
			  JOIN users u ON x.master_pubkey = u.master_pubkey
			  JOIN social_profiles s ON x.master_pubkey = s.master_pubkey
`

	results, err := storage.Select[LiteUser](ctx, a.db, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get random content creators")
	}
	if len(results) == 0 {
		return []*LiteUser{}, nil
	}

	return results, nil
}

func (a *accounts) fetchAndUpdateRelays(ctx context.Context, userID string, followees []string) (relays []*UserAssignedRelay, err error) {
	now := time.Now()
	if relays, err = a.relaysRepo.IONConnectRelaysForUser(ctx, userID); err != nil {
		return nil, errors.Wrapf(err, "cannot fetch relay list from relays managenent for user %v", userID)
	}
	if len(relays) > 0 {
		relayUrls := make([]string, 0, len(relays))
		for _, relay := range relays {
			relayUrls = append(relayUrls, relay.URL)
		}
		var usr *user
		usr, err = storage.ExecOne[user](ctx, a.db, `
					INSERT INTO 
    					users (created_at, updated_at, id, ion_connect_relays, identity_key_name, clients, master_pubkey) VALUES ($3,$3,$1, $2, $1,$4, $1) 
    				ON CONFLICT(id) DO UPDATE 
    					SET 
    					    ion_connect_relays = $2,
    					    updated_at = $3
    				WHERE users.ion_connect_relays IS NULL RETURNING 
    						created_at,
							updated_at,
							id,                           
							identity_key_name,
							master_pubkey,
							clients,
							email,
							phone_number,
							totp_authenticator_secret,
							(SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x) AS ion_connect_relays,
			  				active_2fa_email,
							active_2fa_phone_number,
							active_2fa_totp_authenticator,
							verified     
    				`, userID, relayUrls, *now.Time, []string{})
		if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
			return nil, errors.Wrapf(err, "failed to persist ion relays for userID %v", userID)
		}
		if usr == nil {
			usr, err = a.getUserByID(ctx, userID)
			if err != nil {
				return nil, errors.Wrapf(err, "race condition but cannot get user for userID %v:", userID)
			}
		}

		return usr.IONConnectRelays, nil
	}

	return relays, nil
}

func (a *accounts) validateFollowees(ctx context.Context, followees []string) error {
	failed := make([]string, 0, len(followees))
	followees = slices.DeleteFunc(followees, func(f string) bool {
		pubkey, err := hex.DecodeString(f)
		if err != nil || len(pubkey) != ed25519.PublicKeySize {
			failed = append(failed, f)

			return true
		}

		return false
	})
	failedFollowees, err := storage.Select[struct {
		Followee string `db:"followee"`
	}](ctx, a.db, `SELECT f.followee FROM (SELECT unnest($1::TEXT[]) as followee) f
            				LEFT JOIN users ON master_pubkey=f.followee
						WHERE users.id IS NULL;`, followees)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			err = nil
		}
		return errors.Wrapf(err, "failed to validate followee list")
	}
	if len(failed) == 0 && len(failedFollowees) == 0 {
		return nil
	}
	for _, f := range failedFollowees {
		failed = append(failed, f.Followee)
	}
	return errors.Wrapf(ErrInvalidFollowees, "contains invalid followees: %v", failed)
}

func (a *accounts) fetchIONIndexers(ctx context.Context, userID string) (relays []string, err error) {
	return []string{}, nil
}

func enhanceRelayURL(relay *UserAssignedRelay) {
	relay.URL = strings.TrimSuffix(relay.URL, "/")
}

func (a *accounts) GetUser(ctx context.Context, userIDOrMasterKey string) (*User, error) {
	dbUsr, err := a.getUserByID(ctx, userIDOrMasterKey)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userIDOrMasterKey)
	}
	var usr = &User{}
	if server.LoggedInUser(ctx) != nil && ((dbUsr != nil && dbUsr.ID == server.LoggedInUser(ctx).UserID()) || userIDOrMasterKey == server.LoggedInUser(ctx).UserID()) {
		delegatedUsr, err := a.delegatedRPClient.GetUser(ctx, server.LoggedInUser(ctx).UserID())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get user from delegated party for ID %v", userIDOrMasterKey)
		}
		usr.User = *delegatedUsr
	}
	if dbUsr != nil {
		usr.IONConnectRelays = dbUsr.IONConnectRelays
		if dbUsr.DuplicateOf != nil {
			duplUser, dErr := a.getUserByID(ctx, *dbUsr.DuplicateOf)
			if dErr != nil {
				return nil, errors.Wrapf(dErr, "failed to fetch duplicate user (%v) for userID %v", *dbUsr.DuplicateOf, userIDOrMasterKey)
			}
			usr.DuplicateOf = &duplUser.MasterPubKey
		}

		for i := range usr.IONConnectRelays {
			enhanceRelayURL(usr.IONConnectRelays[i])
		}
		usr.MasterPubKey = dbUsr.MasterPubKey
		usr.IONConnectIndexerRelays, err = a.GetIONConnectIndexerRelays(ctx, userIDOrMasterKey)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch indexers for userID %v", userIDOrMasterKey)
		}
		if server.LoggedInUser(ctx) != nil && dbUsr.ID == server.LoggedInUser(ctx).UserID() {
			twoFAOptions := make([]TwoFAOptionEnum, 0, len(AllTwoFAOptions))
			if len(dbUsr.Email) > 0 {
				if dbUsr.Active2FAEmail != nil && slices.Contains(dbUsr.Active2FAEmail, true) {
					twoFAOptions = append(twoFAOptions, TwoFAOptionEmail)
				}
				usr.Email = dbUsr.Email

			}
			if len(dbUsr.PhoneNumber) > 0 {
				if dbUsr.Active2FAPhoneNumber != nil && slices.Contains(dbUsr.Active2FAPhoneNumber, true) {
					twoFAOptions = append(twoFAOptions, TwoFAOptionSMS)
				}
				usr.PhoneNumber = dbUsr.PhoneNumber
			}
			if len(dbUsr.TotpAuthenticatorSecret) > 0 && dbUsr.Active2FATotpAuthenticator != nil && slices.Contains(dbUsr.Active2FATotpAuthenticator, true) {
				twoFAOptions = append(twoFAOptions, TwoFAOptionTOTPAuthenticator)
			}
			usr.TwoFAOptions = twoFAOptions
		}
	}
	if usr.User == nil && dbUsr == nil {
		return nil, ErrNotFound
	}
	return usr, nil
}

func (a *accounts) upsertUserAfterRegistrationAndCreateWalletView(ctx context.Context, now *time.Time, res map[string]any, visitorID, devicePubkey, earlyAccessEmail string) (*string, string, error) {
	userID, username := dfns.ExtractUser(res, "username")
	walletID, walletPubKey := dfns.ExtractMainWallet(res)
	bscWallet, _ := dfns.ExtractMainWallet(res, dfns.BscWalletNetworkMainNet, dfns.BscWalletNetworkTestNet)
	usr, err := a.upsertUserFromRegistration(ctx, now, res, walletPubKey, visitorID, devicePubkey, earlyAccessEmail)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to upsert users masterkey and visitorId")
	}
	if _, err = a.createDefaultWalletView(ctx, userID, username, walletID, bscWallet, false); err != nil {
		return nil, "", errors.Wrapf(err, "failed to create default walletview for user %v", userID)
	}
	return usr.DuplicateOf, usr.MasterPubKey, nil
}

func (a *accounts) createDefaultWalletView(ctx context.Context, userID, username, walletID, bscWallet string, linkToTON bool) (*WalletView, error) {
	coins := []*CoinMapping{}
	for _, dc := range a.cfg.DefaultCoinsInWalletView {
		defCoins, has := defaultCoins[dc]
		if !has {
			continue
		}
		for _, c := range defCoins {
			if !linkToTON && c.SymbolGroup == defaultWalletViewCoinSymbolGroup && (strings.EqualFold(c.Network, dfns.DefaultWalletNetworkTestNet) || strings.EqualFold(c.Network, dfns.DefaultWalletNetworkMainNet)) {
				coins = append(coins, &CoinMapping{
					WalletID: &walletID,
					CoinID:   c.ID,
				})
				// old accounts with ton
			} else if linkToTON && c.SymbolGroup == defaultWalletViewCoinSymbolGroupForOldAccounts && (strings.EqualFold(c.Network, dfns.DefaultWalletNetworkMainNetForOldAccounts) || strings.EqualFold(c.Network, dfns.DefaultWalletNetworkTestNetForOldAccounts)) {
				coins = append(coins, &CoinMapping{
					WalletID: &walletID,
					CoinID:   c.ID,
				})
			} else if strings.EqualFold(c.Network, dfns.BscWalletNetworkMainNet) || strings.EqualFold(c.Network, dfns.BscWalletNetworkTestNet) {
				coins = append(coins, &CoinMapping{
					WalletID: &bscWallet,
					CoinID:   c.ID,
				})
			} else {
				coins = append(coins, &CoinMapping{
					WalletID: nil,
					CoinID:   c.ID,
				})
			}
		}
	}
	return a.createWalletView(ctx, userID, defaultWalletViewName, coins, a.cfg.DefaultCoinsInWalletView, true)
}

func (a *accounts) upsertUserFromRegistration(ctx context.Context, now *time.Time, res map[string]any, walletPubKey, visitorID, devicePubkey, earlyAccessEmail string) (*user, error) {
	userID, username := dfns.ExtractUser(res, "username")
	if userID == "" && username == "" {
		return nil, nil
	}
	pubkey, err := hex.DecodeString(walletPubKey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		log.Fatal(fmt.Sprintf("Wallet master key does not seems to be EdDSA/ed25519: \"%v\"! User %v %v", walletPubKey, userID, username))
	}

	usr, err := a.insertIdentityKeyNameWithPubKeyAndVisitorID(ctx, now, userID, username, walletPubKey, visitorID, devicePubkey, earlyAccessEmail)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to store wallet pubkey for user %v on registration", userID)
	}
	return usr, nil

}
func (a *accounts) upsertUserFromLogin(r *http.Request, now *time.Time, res map[string]any) error {
	ctx := r.Context()
	var token string
	if tokenI, hasToken := res["token"]; hasToken {
		token = tokenI.(string)
	}
	if token == "" { //nolint:gosec // .
		return nil
	}
	parsedToken, err := server.Auth(ctx).VerifyToken(ctx, token)
	if err != nil {
		log.Panic(errors.Wrapf(err, "we're unable to verify just issued token from 3rd party delegated rp, something changed? Token %v", token))
	}

	wallets, err := a.delegatedRPClient.ListWallets(ctx, parsedToken.UserID())
	if err != nil {
		return errors.Wrapf(err, "failed to get wallets for user %v", parsedToken.UserID())
	}
	masterPubKey := parsedToken.UserID()
	for _, wallet := range wallets {
		if walletID, walletPubKey := dfns.CheckMainWallet(wallet); walletID != "" && walletPubKey != "" {
			masterPubKey = walletPubKey
		}
	}
	var requestID, visitorID, devicePubkey string
	if r.URL.Path == completeLoginUrl {
		requestID = r.Header.Get("X-Device-Identification-Request-ID")
		clientIP := ""
		remoteHeaders := []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"}
		for _, h := range remoteHeaders {
			clientIP = r.Header.Get(h)
			if clientIP != "" {
				break
			}
		}
		ctx = context.WithValue(ctx, clientIPCtxValueKey, clientIP)
		if visitorID, devicePubkey, err = a.validateRequestIDAndExtractVisitor(ctx, now, requestID); err != nil {
			return errors.Wrapf(err, "failed to validate visitor id")
		}
	}
	return errors.Wrapf(a.insertIdentityKeyNameAndVisitorID(ctx, now, parsedToken.UserID(), parsedToken.Username(), masterPubKey, visitorID, devicePubkey),
		"failed to store identity key name %v for user %v on registration", parsedToken.Username(), parsedToken.UserID())
}

func (a *accounts) insertIdentityKeyNameAndVisitorID(ctx context.Context, now *time.Time, userID, identityKeyName, masterPubKey, visitorID, devicePubkey string) error {
	visitorUpdate := `SELECT 1;`
	params := []any{userID, identityKeyName, []string{}, *now.Time, masterPubKey}
	if visitorID != "" {
		visitorUpdate = `INSERT INTO users_visitors(created_at, user_id, visitor_id, device_pubkey) VALUES ($4, $1, $6, $7)
							ON CONFLICT(user_id, visitor_id) DO UPDATE SET device_pubkey = $7;`
		params = append(params, visitorID, devicePubkey)
	}
	_, err := storage.Exec(ctx, a.db, fmt.Sprintf(`
								WITH users_insert AS (
									INSERT INTO users(created_at, updated_at, id, identity_key_name, clients, master_pubkey) VALUES ($4,$4,$1,$2,$3,$5) 
                                                ON CONFLICT(id) DO UPDATE SET 
    										    identity_key_name = $2,
    										    updated_at = $4,
												master_pubkey = $5
                                            WHERE users.identity_key_name = users.id OR users.master_pubkey = users.id
									)
								%v`, visitorUpdate), params...)

	return errors.Wrapf(err, "failed to update user with identity key name in db %v %v", userID, identityKeyName)
}
func (a *accounts) insertIdentityKeyNameWithPubKeyAndVisitorID(ctx context.Context, now *time.Time, userID, identityKeyName, walletPubkey, visitorID, devicePubkey, earlyAccessEmail string) (*user, error) {
	emailUpdate := ""
	params := []any{userID, identityKeyName, []string{}, *now.Time, walletPubkey, visitorID, devicePubkey}
	if earlyAccessEmail != "" {
		emailUpdate = `email_update AS (
			UPDATE assigned_early_access_emails SET
				email = $8
			WHERE email = $2 AND user_id = $1
		),`
		params = append(params, earlyAccessEmail)
	}
	sql := fmt.Sprintf(`
	WITH %v visitor_update AS (
		UPDATE users_visitors SET 
			visitor_id = $6,
			device_pubkey = $7,
			created_at = $4
		WHERE user_id = $1 AND visitor_id = $1
	),
	duplicate AS (
		SELECT user_id FROM users_visitors WHERE visitor_id = $6 AND user_id != $1 ORDER BY created_at ASC LIMIT 1
	) 
	INSERT INTO users(created_at, updated_at, id, identity_key_name, clients, master_pubkey, duplicate_of) VALUES ($4,$4,$1,$2,$3, $5, (SELECT user_id FROM duplicate)) 
                                            ON CONFLICT(id) DO UPDATE SET 
    										    master_pubkey = $5,
    										    updated_at = $4,
    										    identity_key_name = $2,
												duplicate_of = (SELECT user_id FROM duplicate)
                                            WHERE users.master_pubkey = users.id
											RETURNING users.duplicate_of, COALESCE((SELECT master_pubkey FROM users WHERE id = (SELECT user_id FROM duplicate) LIMIT 1),'') as master_pubkey`, emailUpdate)
	usr, err := storage.ExecOne[user](ctx, a.db, sql, params...)

	return usr, errors.Wrapf(err, "failed to update user with pubkey in db %v %v", userID, walletPubkey)
}

func (u *User) MarshalJSON() ([]byte, error) {
	if u == nil {
		return []byte("null"), nil
	}
	values := map[string]any{}
	if u.User != nil {
		values = u.User
	}
	rUser := reflect.TypeOf(u).Elem()
	rUserVal := reflect.Indirect(reflect.ValueOf(u))
	for i := range rUser.NumField() {
		field := rUser.Field(i)
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			var opt string
			jsonTag, opt, _ = strings.Cut(jsonTag, ",")
			val := rUserVal.FieldByName(field.Name)
			if opt == "omitempty" && isEmptyValue(val) {
				continue
			}
			values[jsonTag] = val.Interface()
		}
	}

	return json.Marshal(values)
}

func isEmptyValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool:
		return !value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return value.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return value.IsNil()
	case reflect.Struct:
		return value.IsZero()
	case reflect.Invalid, reflect.Complex64, reflect.Complex128, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return false
	default:
		return value.IsZero()
	}
}

func (a *accounts) DeleteUser(ctx context.Context, userID string) error {
	usr, err := a.getUserByID(ctx, userID)
	if err != nil || usr == nil {
		if usr == nil || errors.Is(err, ErrNotFound) {
			return ErrNotChanged
		}

		return errors.Wrapf(err, "failed to delete user %v", userID)
	}
	now := time.Now()
	if sErr := a.verifyUserSignatureFromIONConnect(userSignature(ctx), now, usr); sErr != nil {
		return errors.Wrapf(sErr, "failed to delete user due to invalid signature")
	}

	return errors.Wrapf(a.deleteUser(ctx, userID), "failed to delete user")
}

func (a *accounts) deleteUser(ctx context.Context, userID string) error {
	rows, err := storage.Exec(ctx, a.db, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return errors.Wrapf(err, "failed to delete user %v", userID)
	}
	if (err == nil && rows == 0) || storage.IsErr(err, storage.ErrNotFound) {
		err = ErrNotChanged
	}

	return errors.Wrapf(err, "failed to delete user data %v", userID)
}

func (a *accounts) verifyUserSignatureFromIONConnect(signatureBase64 string, now *time.Time, usr *user) error {
	bToken, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "failed to unmarshal auth token: malformed base64: %q", signatureBase64)
	}

	var event nostr.Event
	if err := event.UnmarshalJSON(bToken); err != nil {
		return errors.Wrap(ErrInvalidUserSignature, "failed to unmarshal auth token: malformed event json")
	}
	hash := sha256.Sum256(event.Serialize())
	if id := hex.EncodeToString(hash[:]); id != event.ID {
		return errors.New("event id is invalid")
	}
	if !strings.HasPrefix(event.Sig, "eddsa/curve25519:") {
		return errors.Wrapf(ErrInvalidUserSignature, "eddsa/curve25519 prefix missing, masterkey is ed25519")
	}
	event.Sig = strings.TrimPrefix(event.Sig, "eddsa/curve25519:")
	sigBytes, err := hex.DecodeString(event.Sig)
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "invalid hex in signature")
	}
	pk, err := hex.DecodeString(event.PubKey)
	if err != nil {
		return errors.Wrapf(ErrInvalidUserSignature, "invalid hex in pubkey")
	}
	if ok := ed25519.Verify(pk, hash[:], sigBytes); !ok {
		return errors.Wrapf(ErrInvalidUserSignature, "invalid signature")
	}
	masterKey := event.PubKey
	if usr.MasterPubKey != masterKey {
		return errors.Wrapf(ErrInvalidUserSignature, "master key mismatch")
	}
	if now.Before(event.CreatedAt.Time()) || (now.After(event.CreatedAt.Time()) && now.Sub(event.CreatedAt.Time()) > a.cfg.UserSignatureExpiration) {
		return errors.Wrapf(ErrInvalidUserSignature, "expired")
	}
	if event.Kind != nostr.KindDeletion {
		return errors.Wrapf(ErrInvalidUserSignature, "kind mismatch")
	}
	return nil
}

func (a *accounts) IsUserVerified(ctx context.Context, masterPubKey string) (bool, []*model.Event, error) {
	query := `SELECT verified FROM users WHERE master_pubkey = $1`
	type result struct {
		Verified bool `db:"verified"`
	}
	res, err := storage.Get[result](ctx, a.db, query, masterPubKey)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to check user verification status")
	}
	if !res.Verified {
		return false, nil, nil
	}
	events, err := generateVerificationEvents(a.privateKey, masterPubKey)
	if err != nil {
		return true, nil, err
	}

	return true, events, nil
}

func (a *accounts) CompleteRegistration(ctx context.Context, credentials *Credentials) (res CompletedRegistration, err error) {
	now := time.Now()
	earlyAccessEmail := credentials.EarlyAccessEmail
	registrationsEnabled, earlyAccess := a.registrationsEnabled()
	if !registrationsEnabled {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrRegistrationsDisabled
		derr.HTTPStatus = http.StatusForbidden
		return nil, derr
	}
	if earlyAccess {
		if strings.TrimSpace(earlyAccessEmail) == "" {
			derr := new(dfns.DfnsInternalError)
			*derr = *ErrEmailNotAllowedForEarlyAccess
			derr.HTTPStatus = http.StatusForbidden
			return nil, derr
		}
	} else {
		earlyAccessEmail = ""
	}
	tok, err := server.Auth(ctx).VerifyToken(ctx, strings.TrimPrefix(authHeader(ctx), "Bearer "))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to verify temporary auth token from registration %v", authHeader(ctx))
	}
	var visitorID, devicePubkey, requestID string
	requestIDVal := ctx.Value(RequestIDCtxValueKey)
	if requestIDVal != nil {
		requestID = requestIDVal.(string)
	}
	if err = a.insertRegistrationComplete(ctx, now, earlyAccessEmail, tok.UserID(), tok.Username(), requestID); err != nil {
		return nil, errors.Wrap(err, "failed to insert registration complete")
	}
	if requestIDVal != nil && requestID != "" {
		visitorID, devicePubkey, err = a.validateRequestIDAndExtractVisitor(ctx, now, requestID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify visitor id")
		}
	}
	registration, err := a.delegatedRPClient.CompleteRegistrationWithWallets(ctx, credentials)
	if err != nil {
		rErr := a.rollbackRegistrationAttempt(tok.Username(), earlyAccessEmail)
		if rErr != nil {
			return nil, errors.Join(err, errors.Wrapf(rErr, "failed to rollback registration attempt (complete) for user %v %v", tok.UserID(), tok.Username()))
		}
		return nil, errors.Wrap(err, "failed to complete registration")
	}
	var duplicateOf *string
	var originLinkedId string
	userID, _ := dfns.ExtractUser(registration, "username")
	duplicateOf, originLinkedId, err = a.upsertUserAfterRegistrationAndCreateWalletView(ctx, now, registration, visitorID, devicePubkey, earlyAccessEmail)
	if err != nil {
		return nil, errors.Wrap(err, "failed to upsert wallet pubkey")
	}
	_, masterPubKey := dfns.ExtractMainWallet(registration)
	if duplicateOf != nil {
		registration["duplicateOf"] = originLinkedId
	}
	if err = a.deviceIdentificationClient.UpdateRequestID(ctx, requestID, masterPubKey, &originLinkedId); err != nil {
		rErr := a.rollbackVisitor(userID, visitorID, duplicateOf)
		if rErr != nil {
			return nil, multierror.Append(err, errors.Wrap(rErr, "failed to rollback visitor link"))
		}
		return nil, errors.Wrapf(err, "failed to update request id for user %v: %v", userID, requestID)
	}

	return registration, nil
}

func (a *accounts) InitRegistration(ctx context.Context, identityKeyName string, earlyAccessEmail string) (res *RegistrationChallenge, err error) {
	now := time.Now()
	registrationsEnabled, earlyAccess := a.registrationsEnabled()
	if !registrationsEnabled {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrRegistrationsDisabled
		derr.HTTPStatus = http.StatusForbidden
		return nil, derr
	}
	if earlyAccess {
		if strings.TrimSpace(earlyAccessEmail) == "" {
			derr := new(dfns.DfnsInternalError)
			*derr = *ErrEmailNotAllowedForEarlyAccess
			derr.HTTPStatus = http.StatusForbidden
			return nil, derr
		}
	} else {
		earlyAccessEmail = ""
	}
	if err = a.insertRegistrationAttempt(ctx, now, identityKeyName, earlyAccessEmail); err != nil {
		return nil, errors.Wrap(err, "failed to insert registration attempt")
	}
	resp, err := a.delegatedRPClient.InitRegistration(ctx, identityKeyName)
	if err != nil {
		if rErr := a.rollbackRegistrationAttempt(identityKeyName, earlyAccessEmail); rErr != nil {
			err = errors.Join(err, errors.Wrap(rErr, "failed to rollback registration attempt"))
		}
		return nil, errors.Wrapf(err, "failed to init registration in 3rd party side for user %v", identityKeyName)
	}
	usrID, respIdentityKeyName := dfns.ExtractUser(*resp, "name")
	if err = a.updateRegistrationAttemptWithUserID(ctx, now, usrID, respIdentityKeyName, earlyAccessEmail); err != nil {
		return nil, errors.Wrapf(err, "failed to update registration attempt for user %v, early access %v", identityKeyName, earlyAccessEmail)
	}
	return resp, nil
}

func (a *accounts) GetIONConnectRelaysForUsers(ctx context.Context, masterPubkeys []string) ([]*LiteUser, error) {
	u, err := storage.Select[LiteUser](ctx, a.db, `SELECT 
	users.master_pubkey, s.username, s.display_name, s.avatar,
    (SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(users.ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x) AS ion_connect_relays
    FROM users 
    JOIN social_profiles s ON users.master_pubkey = s.master_pubkey
    where users.master_pubkey = ANY($1)`, masterPubkeys)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get users relays for pubkeys %#v", masterPubkeys)
	}
	if len(u) == 0 {
		return []*LiteUser{}, nil
	}
	return u, nil
}

func (a *accounts) GetGlobalAccounts(ctx context.Context, currentVer uint64) ([]*LiteUser, uint64, error) {
	stmt := `SELECT CAST(value AS BIGINT) as latest_version
			 FROM global 
			 WHERE key = 'latest_global_accounts_version'
               AND CAST(value AS BIGINT) > $1`
	lv, err := storage.Get[struct {
		LatestVersion uint64 `db:"latest_version"`
	}](ctx, a.db, stmt, currentVer)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return []*LiteUser{}, currentVer, nil
		}

		return nil, 0, errors.Wrapf(err, "failed to select latest_global_accounts_version for version: %#v", currentVer)
	}
	stmt = `SELECT 
					global_accounts.master_pubkey,
    				(SELECT json_agg(x) FROM (SELECT userurl as url, relay_type as "type" FROM ion_connect_relays join unnest(users.ion_connect_relays) AS t(userurl) ON url = userurl OR url = replace(userurl, ':4443','')) x) AS ion_connect_relays,
    				s.username, s.display_name, s.avatar
    		 FROM global_accounts
				JOIN users ON users.master_pubkey = global_accounts.master_pubkey
				JOIN social_profiles s ON users.master_pubkey = s.master_pubkey
				`
	accs, err := storage.Select[LiteUser](ctx, a.db, stmt)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to select GlobalAccounts for version: %#v", currentVer)
	}
	if accs == nil {
		accs = []*LiteUser{}
	}

	return accs, lv.LatestVersion, nil
}

func (a *accounts) GetNSFWAccounts(ctx context.Context, currentVer uint64) ([]string, uint64, error) {
	stmt := `SELECT CAST(value AS BIGINT) as latest_version
			 FROM global 
			 WHERE key = 'latest_nsfw_accounts_version'
               AND CAST(value AS BIGINT) > $1`
	lv, err := storage.Get[struct {
		LatestVersion uint64 `db:"latest_version"`
	}](ctx, a.db, stmt, currentVer)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return []string{}, currentVer, nil
		}

		return nil, 0, errors.Wrapf(err, "failed to select latest_nsfw_accounts_version for version: %#v", currentVer)
	}
	stmt = `SELECT master_pubkey FROM nsfw_accounts`
	accs, err := storage.Select[struct {
		MasterPubkey string `db:"master_pubkey"`
	}](ctx, a.db, stmt)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to select NSFWAccounts for version: %#v", currentVer)
	}

	masterPubkeys := make([]string, 0, len(accs))
	for _, acc := range accs {
		masterPubkeys = append(masterPubkeys, acc.MasterPubkey)
	}

	return masterPubkeys, lv.LatestVersion, nil
}

func (a *accounts) rollbackVisitor(userID, visitorID string, duplicateOf *string) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
	defer cancel()
	rollbackDuplicateOf := ""
	if duplicateOf != nil {
		rollbackDuplicateOf = `WITH duplicate_rollback AS (
			UPDATE users SET duplicate_of = NULL WHERE id = $2
		)`
	}
	_, err := storage.Exec(rollbackCtx, a.db,
		fmt.Sprintf(`%v DELETE FROM users_visitors WHERE visitor_id = $1 and user_id = $2`, rollbackDuplicateOf), visitorID, userID,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to rollback visitor for user %v", userID)
	}
	return nil
}

func (a *accounts) insertRegistrationAttempt(ctx context.Context, now *time.Time, identityKeyName, earlyAccessEmail string) error {
	params := []any{identityKeyName, []string{}, *now.Time}
	earlyAccessEmailClause := "SELECT true as email_allowed;"
	type emailAllowed struct {
		EmailAllowed bool `db:"email_allowed"`
	}
	if earlyAccessEmail != "" {
		maxAllowedPerEmail := a.appsRuntimeConfig.IONApp.MaxEarlyAccessRegistrationsAllowedPerEmail
		earlyAccessEmailClause = `, ins_email as (WITH allowed_email AS (
				SELECT * FROM (VALUES($1, $1)) as t(email, user_id) WHERE (SELECT count(*) FROM assigned_early_access_emails WHERE email = $4) < $5
			)
			INSERT INTO assigned_early_access_emails(email, user_id) SELECT email, user_id FROM allowed_email ON CONFLICT(email, user_id) 
			DO UPDATE SET user_id = excluded.user_id
			RETURNING 1) SELECT count(*) > 0 AS email_allowed from ins_email;`
		params = append(params, earlyAccessEmail, maxAllowedPerEmail)
	}
	sql := fmt.Sprintf(`WITH ins_user AS (
				INSERT INTO users(created_at, updated_at, id, identity_key_name, clients, master_pubkey) 
					  	  VALUES ($3,         $3,         $1 ,$1,                $2,      $1)
                                                ON CONFLICT(id) DO NOTHING
						  RETURNING 1
				) 
			%v;`, earlyAccessEmailClause)
	allowed, err := storage.ExecOne[emailAllowed](ctx, a.db, sql, params...)
	if err != nil {
		switch {
		case storage.IsErr(err, storage.ErrRelationNotFound):
			err = nil
			allowed = &emailAllowed{EmailAllowed: false}
		case storage.IsErr(err, storage.ErrDuplicate):
			// retry from FE due to webauthn failure probably, its challenge endpoint
			if tErr := terror.As(err); tErr != nil && tErr.Data["column"] == "identityname" {
				err = nil
				allowed = &emailAllowed{EmailAllowed: true}
			}
		default:
			return errors.Wrapf(err, "failed to check if email %v is allowed and insert user %v", earlyAccessEmail, identityKeyName)
		}
	}
	if allowed == nil {
		if earlyAccessEmail != "" {
			allowed = &emailAllowed{EmailAllowed: false}
		} else {
			allowed = &emailAllowed{EmailAllowed: true}
		}
	}
	if !allowed.EmailAllowed {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	return nil
}
func (a *accounts) updateRegistrationAttemptWithUserID(ctx context.Context, now *time.Time, userID, identityKeyName, earlyAccessEmail string) error {
	params := []any{userID, identityKeyName, *now.Time}
	earlyAccessEmailClause := "SELECT 1;"
	if earlyAccessEmail != "" {
		earlyAccessEmailClause = `UPDATE assigned_early_access_emails SET user_id = $1 WHERE email = $2 AND user_id = $2`
	}
	sql := fmt.Sprintf(`WITH upd_user AS (
				UPDATE users SET updated_at = $3, 
								 id = $1,
								 master_pubkey = $1
                WHERE id = $2 AND identity_key_name = id
				) 
			%v`, earlyAccessEmailClause)
	_, err := storage.Exec(ctx, a.db, sql, params...)
	if err != nil {
		return errors.Wrapf(err, "failed to update pre-registered user %v", identityKeyName)
	}
	return nil
}

func (a *accounts) rollbackRegistrationAttempt(identityKeyName, earlyAccessEmail string) (err error) {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
	defer cancel()
	_, err = storage.Exec(rollbackCtx, a.db, `WITH email_del AS (
		DELETE from assigned_early_access_emails WHERE email = $1 and user_id = $1
	)
	DELETE FROM users WHERE id = identity_key_name and id = $1`, identityKeyName,
	)

	return errors.Wrapf(err, "failed to rollback registration attempt for user %v", identityKeyName)
}
