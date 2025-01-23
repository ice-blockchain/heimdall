// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"golang.org/x/exp/rand"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) getUserByID(ctx context.Context, userID string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT * FROM users where id = $1 or master_pubkey = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by ID %v", userID)
	}
	return u, nil
}
func (a *accounts) getUserByUsername(ctx context.Context, username string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT * FROM users where username = $1`, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by username %v", username)
	}
	return u, nil
}
func clientIPAddress(ctx context.Context) string {
	return ctx.Value(clientIPCtxValueKey).(string)
}
func (a *accounts) GetOrAssignIONConnectRelays(ctx context.Context, userID string, followees []string) (relays []string, err error) {
	usr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to check if user already have ion relays")
	}
	if len(usr.IONConnectRelays) > 0 {
		return usr.IONConnectRelays, nil
	}
	if err = a.validateFollowees(ctx, followees); err != nil {
		return nil, errors.Wrapf(err, "failed to validate followees pubkeys")
	}

	return a.fetchAndUpdateRelaysFromPolaris(ctx, userID, followees)
}
func (a *accounts) GetIONConnectIndexerRelays(ctx context.Context, userID string) (indexers []string, err error) {
	return a.fetchIONIndexers(ctx, userID)
}

func (a *accounts) fetchAndUpdateRelaysFromPolaris(ctx context.Context, userID string, followees []string) (relays []string, err error) {
	now := time.Now()
	if relays, err = a.fetchRelays(ctx, userID, followees); err != nil {
		return nil, errors.Wrapf(err, "cannot fetch relay list from polaris")
	}
	if len(relays) > 0 {
		var usr *user
		usr, err = storage.ExecOne[user](ctx, a.db, `
					INSERT INTO 
    					users (created_at, updated_at, id, ion_connect_relays, username, clients, master_pubkey) VALUES ($3,$3,$1, $2, $1,$4, $1) 
    				ON CONFLICT(id) DO UPDATE 
    					SET 
    					    ion_connect_relays = $2,
    					    updated_at = $3
    				WHERE users.ion_connect_relays IS NULL RETURNING *`, userID, relays, *now.Time, []string{})
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

func (a *accounts) fetchRelays(ctx context.Context, userID string, followeeList []string) (relays []string, err error) {
	randomRelay := a.cfg.MockRelays[rand.Intn(len(a.cfg.MockRelays))]
	return []string{randomRelay}, nil
}

func (a *accounts) fetchIONIndexers(ctx context.Context, userID string) (relays []string, err error) {
	log.Info("Fetching indexers from polaris for %v", clientIPAddress(ctx))
	randomIndexer := a.cfg.MockRelays[rand.Intn(len(a.cfg.MockRelays))]
	return []string{randomIndexer}, nil
}

func (a *accounts) GetUser(ctx context.Context, userIDOrMasterKey string) (*User, error) {
	dbUsr, err := a.getUserByID(ctx, userIDOrMasterKey)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userIDOrMasterKey)
	}
	var usr = &User{}
	if server.LoggedInUser(ctx) != nil && (dbUsr != nil && dbUsr.ID == server.LoggedInUser(ctx).UserID()) || userIDOrMasterKey == server.LoggedInUser(ctx).UserID() {
		delegatedUsr, err := a.delegatedRPClient.GetUser(ctx, server.LoggedInUser(ctx).UserID())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get user from delegated party for ID %v", userIDOrMasterKey)
		}
		usr.User = *delegatedUsr
	}
	if dbUsr != nil {
		usr.IONConnectRelays = dbUsr.IONConnectRelays
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

func (a *accounts) upsertUsernameFromRegistration(ctx context.Context, now *time.Time, res map[string]any) error {
	userID, username := dfns.ExtractUser(res, "name")
	if userID == "" && username == "" {
		return nil
	}
	return errors.Wrapf(a.insertUsername(ctx, now, userID, username, userID), "failed to store username %v for user %v on registration", username, userID)
}
func (a *accounts) upsertWalletPubKeyFromRegistrationAndRegisterWalletView(ctx context.Context, now *time.Time, res map[string]any) error {
	userID, username := dfns.ExtractUser(res, "username")
	walletID, walletPubKey := dfns.ExtractMainWallet(res)
	if err := a.upsertWalletPubKeyFromRegistration(ctx, now, res, walletPubKey); err != nil {
		return errors.Wrapf(err, "failed to upsert users masterkey")
	}
	if _, err := a.CreateWalletView(ctx, userID, username, []*CoinMapping{
		{WalletID: &walletID, CoinID: defaultWalletViewCoinID},
	}, []string{defaultWalletViewCoinSymbolGroup}); err != nil {
		return errors.Wrapf(err, "failed to create default walletview for user %v", userID)
	}

	return nil
}

func (a *accounts) upsertWalletPubKeyFromRegistration(ctx context.Context, now *time.Time, res map[string]any, walletPubKey string) error {
	userID, username := dfns.ExtractUser(res, "username")
	if userID == "" && username == "" {
		return nil
	}
	pubkey, err := hex.DecodeString(walletPubKey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		log.Fatal("Wallet master key does not seems to be EdDSA/ed25519!")
	}

	return errors.Wrapf(a.insertUsernameWithPubKey(ctx, now, userID, username, walletPubKey),
		"failed to store wallet pubkey for user %v on registration", userID)
}
func (a *accounts) upsertUsernameFromLogin(ctx context.Context, now *time.Time, res map[string]any) error {
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

	return errors.Wrapf(a.insertUsername(ctx, now, parsedToken.UserID(), parsedToken.Username(), masterPubKey),
		"failed to store username %v for user %v on registration", parsedToken.Username(), parsedToken.UserID())
}

func (a *accounts) insertUsername(ctx context.Context, now *time.Time, userID, username, masterPubKey string) error {
	_, err := storage.Exec(ctx, a.db, `INSERT INTO users(created_at, updated_at, id, username, clients, master_pubkey) VALUES ($4,$4,$1,$2,$3,$5) 
                                                ON CONFLICT(id) DO UPDATE SET 
    										    username = $2,
    										    updated_at = $4,
												master_pubkey = $5
                                            WHERE users.username = users.id OR users.master_pubkey = users.id`, userID, username, []string{}, *now.Time, masterPubKey)

	return errors.Wrapf(err, "failed to update user with username in db %v %v", userID, username)
}
func (a *accounts) insertUsernameWithPubKey(ctx context.Context, now *time.Time, userID, username, walletPubkey string) error {
	_, err := storage.Exec(ctx, a.db, `INSERT INTO users(created_at, updated_at, id, username, clients, master_pubkey) VALUES ($4,$4,$1,$2,$3, $5)
                                            ON CONFLICT(id) DO UPDATE SET 
    										    master_pubkey = $5,
    										    updated_at = $4
                                            WHERE users.master_pubkey = users.id`, userID, username, []string{}, *now.Time, walletPubkey)

	return errors.Wrapf(err, "failed to update user with piubkey in db %v %v", userID, walletPubkey)
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
