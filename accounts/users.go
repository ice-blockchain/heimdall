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

	"github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
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
    (select json_agg(x) from (select url, relay_type as "type" from ion_connect_relays where url=ANY(users.ion_connect_relays)) x) as ion_connect_relays,
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
		(select json_agg(x) from (select url, relay_type as "type" from ion_connect_relays where url=ANY(users.ion_connect_relays)) x) as ion_connect_relays,
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
	query := `SELECT x.master_pubkey, 
       		  (SELECT json_agg(x) FROM (SELECT url, relay_type as "type" from ion_connect_relays where url=ANY(u.ion_connect_relays)) x) as ion_connect_relays
			  FROM (SELECT master_pubkey FROM content_creators ` + excludeClause + ` 
			  ORDER BY random() LIMIT $` + strconv.Itoa(len(args)) + `) x
			  JOIN users u ON x.master_pubkey = u.master_pubkey`

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
							(SELECT json_agg(x) FROM (SELECT url, relay_type as "type" from ion_connect_relays where url=ANY(ion_connect_relays)) x) as ion_connect_relays,
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
	log.Info("Fetching indexers from polaris for %v", clientIPAddress(ctx))
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

func (a *accounts) upsertUserAfterRegistrationAndCreateWalletView(ctx context.Context, now *time.Time, res map[string]any, visitorID, devicePubkey string) (*string, string, error) {
	userID, username := dfns.ExtractUser(res, "username")
	walletID, walletPubKey := dfns.ExtractMainWallet(res)
	usr, err := a.upsertUserFromRegistration(ctx, now, res, walletPubKey, visitorID, devicePubkey)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to upsert users masterkey and visitorId")
	}
	if _, err := a.createDefaultWalletView(ctx, userID, username, walletID, false); err != nil {
		return nil, "", errors.Wrapf(err, "failed to create default walletview for user %v", userID)
	}
	return usr.DuplicateOf, usr.MasterPubKey, nil
}

func (a *accounts) createDefaultWalletView(ctx context.Context, userID, username, walletID string, linkToTON bool) (*WalletView, error) {
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

func (a *accounts) upsertUserFromRegistration(ctx context.Context, now *time.Time, res map[string]any, walletPubKey, visitorID, devicePubkey string) (*user, error) {
	userID, username := dfns.ExtractUser(res, "username")
	if userID == "" && username == "" {
		return nil, nil
	}
	pubkey, err := hex.DecodeString(walletPubKey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		log.Fatal(fmt.Sprintf("Wallet master key does not seems to be EdDSA/ed25519: \"%v\"! User %v %v", walletPubKey, userID, username))
	}

	usr, err := a.insertIdentityKeyNameWithPubKeyAndVisitorID(ctx, now, userID, username, walletPubKey, visitorID, devicePubkey)
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
							ON CONFLICT(user_id, visitor_id) DO NOTHING;`
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
func (a *accounts) insertIdentityKeyNameWithPubKeyAndVisitorID(ctx context.Context, now *time.Time, userID, identityKeyName, walletPubkey, visitorID, devicePubkey string) (*user, error) {
	usr, err := storage.ExecOne[user](ctx, a.db, `WITH visitor_insert AS (
		INSERT INTO users_visitors(created_at, user_id, visitor_id, device_pubkey) VALUES ($4, $1, $6, $7)
		ON CONFLICT(user_id, visitor_id) DO NOTHING
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
											RETURNING users.duplicate_of, COALESCE((SELECT master_pubkey FROM users WHERE id = (SELECT user_id FROM duplicate) LIMIT 1),'') as master_pubkey`, userID, identityKeyName, []string{}, *now.Time, walletPubkey, visitorID, devicePubkey)

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
	if err := a.VerifyEarlyAccess(ctx, earlyAccessEmail); err != nil {
		return nil, err
	}
	var visitorID, devicePubkey, requestID string
	requestIDVal := ctx.Value(RequestIDCtxValueKey)
	if requestIDVal != nil {
		requestID = requestIDVal.(string)
		visitorID, devicePubkey, err = a.validateRequestIDAndExtractVisitor(ctx, now, requestID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify visitor id")
		}
	}
	registration, err := a.delegatedRPClient.CompleteRegistrationWithWallets(ctx, credentials)
	if err != nil {
		return nil, errors.Wrap(err, "failed to complete registration")
	}
	if err = a.verifyEarlyAccessAndUpsertUserID(ctx, earlyAccessEmail, registration); err != nil {
		return nil, errors.Wrap(err, "failed update early access state")
	}
	var duplicateOf *string
	var originLinkedId string
	userID, _ := dfns.ExtractUser(registration, "username")
	duplicateOf, originLinkedId, err = a.upsertUserAfterRegistrationAndCreateWalletView(ctx, now, registration, visitorID, devicePubkey)
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
		return registration, nil
	}

	return registration, nil
}

func (a *accounts) GetIONConnectRelaysForUsers(ctx context.Context, masterPubkeys []string) ([]*LiteUser, error) {
	u, err := storage.Select[LiteUser](ctx, a.db, `SELECT 
	master_pubkey,
    (select json_agg(x) from (select url, relay_type as "type" from ion_connect_relays where url=ANY(users.ion_connect_relays)) x) as ion_connect_relays
    FROM users where master_pubkey = ANY($1)`, masterPubkeys)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get users relays for pubkeys %#v", masterPubkeys)
	}
	if len(u) == 0 {
		return []*LiteUser{}, nil
	}
	return u, nil
}

func (a *accounts) GetGlobalAccounts(ctx context.Context, currentVer uint8) ([]*LiteUser, uint8, error) {
	stmt := `SELECT CAST(value AS INTEGER) as latest_version
			 FROM global 
			 WHERE key = 'latest_global_accounts_version'
               AND CAST(value AS INTEGER) > $1`
	lv, err := storage.Get[struct {
		LatestVersion uint8 `db:"latest_version"`
	}](ctx, a.db, stmt, currentVer)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return []*LiteUser{}, currentVer, nil
		}

		return nil, 0, errors.Wrapf(err, "failed to select latest_global_accounts_version for version: %#v", currentVer)
	}
	stmt = `SELECT 
					global_accounts.master_pubkey,
    				(select json_agg(x) 
					 from 
						(select url, 
								relay_type as "type" 	
						from ion_connect_relays 
						where url=ANY(users.ion_connect_relays)) x
				    ) as ion_connect_relays
    		 FROM global_accounts
				JOIN users 
                  ON users.master_pubkey = global_accounts.master_pubkey`
	accs, err := storage.Select[LiteUser](ctx, a.db, stmt)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to select GlobalAccounts for version: %#v", currentVer)
	}
	if accs == nil {
		accs = []*LiteUser{}
	}

	return accs, lv.LatestVersion, nil
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
