// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"io"
	"reflect"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) getUserByID(ctx context.Context, userID string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT * FROM users where id = $1`, userID)
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
    					users (created_at, updated_at, id, ion_connect_relays, username, clients) VALUES ($3,$3,$1, $2, $1,$4) 
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

func (a *accounts) fetchRelays(ctx context.Context, userID string, followeeList []string) (relays []string, err error) {
	log.Info("Fetching relay from polaris for %v", clientIPAddress(ctx))
	return []string{"ws://example1.com/", "wss://example2.com/", "ws://example3.com/ws"}, nil
}
func (a *accounts) fetchIONIndexers(ctx context.Context, userID string) (relays []string, err error) {
	log.Info("Fetching indexers from polaris for %v", clientIPAddress(ctx))
	return []string{"ws://indexer-example1.com/", "wss://indexer-example2.com/", "wss://indexer-example3.com/ws"}, nil
}

func (a *accounts) GetUser(ctx context.Context, userID string) (*User, error) {
	dbUsr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userID)
	}
	delegatedUsr, err := a.delegatedRPClient.GetUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user from delegated party for ID %v", userID)
	}
	usr := &User{User: *delegatedUsr}
	if dbUsr != nil {
		usr.IONConnectRelays = dbUsr.IONConnectRelays
		usr.IONConnectIndexerRelays, err = a.GetIONConnectIndexerRelays(ctx, userID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch indexers for userID %v", userID)
		}
		twoFAOptions := make([]TwoFAOptionEnum, 0, len(AllTwoFAOptions))
		if len(dbUsr.Email) > 0 {
			if dbUsr.Active2FAEmail != nil {
				twoFAOptions = append(twoFAOptions, TwoFAOptionEmail)
			}
			usr.Email = dbUsr.Email

		}
		if len(dbUsr.PhoneNumber) > 0 {
			if dbUsr.Active2FAPhoneNumber != nil {
				twoFAOptions = append(twoFAOptions, TwoFAOptionSMS)
			}
			usr.PhoneNumber = dbUsr.PhoneNumber
		}
		if len(dbUsr.TotpAuthenticatorSecret) > 0 && dbUsr.Active2FATotpAuthenticator != nil {
			twoFAOptions = append(twoFAOptions, TwoFAOptionTOTPAuthenticator)
		}
		usr.TwoFAOptions = twoFAOptions
	}
	return usr, nil
}

func (a *accounts) upsertUsernameFromRegistration(ctx context.Context, now *time.Time, body io.Reader) error {
	respData, err := io.ReadAll(body)
	if err != nil {
		return errors.Wrapf(err, "failed to read delegated relying party body")
	}
	var res map[string]any
	if err = json.UnmarshalContext(ctx, respData, &res); err != nil {
		return errors.Wrapf(err, "failed to parse json for %v", string(respData))
	}
	var usr map[string]any
	if userInferface, hasUser := res["user"]; hasUser {
		usr = userInferface.(map[string]any)
	}
	if len(usr) == 0 {
		return nil
	}
	userID := usr["id"].(string)
	username := usr["name"].(string)
	return errors.Wrapf(a.insertUsername(ctx, now, userID, username), "failed to store username %v for user %v on registration", username, userID)
}

func (a *accounts) upsertUsernameFromLogin(ctx context.Context, now *time.Time, body io.Reader) error {
	respData, err := io.ReadAll(body)
	if err != nil {
		return errors.Wrapf(err, "failed to read delegated relying party body")
	}
	var res map[string]any
	if err = json.UnmarshalContext(ctx, respData, &res); err != nil {
		return errors.Wrapf(err, "failed to parse json for %v", string(respData))
	}
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

	return errors.Wrapf(a.insertUsername(ctx, now, parsedToken.UserID(), parsedToken.Username()),
		"failed to store username %v for user %v on registration", parsedToken.Username(), parsedToken.UserID())
}

func (a *accounts) insertUsername(ctx context.Context, now *time.Time, userID, username string) error {
	_, err := storage.Exec(ctx, a.db, `INSERT INTO users(created_at, updated_at, id, username, clients) VALUES ($4,$4,$1,$2,$3) ON CONFLICT(id) DO UPDATE 
    										SET 
    										    username = $2,
    										    updated_at = $4
                                            WHERE users.username = users.id`, userID, username, []string{}, *now.Time)
	return errors.Wrapf(err, "failed to update user with username in db %v %v", userID, username, []string{}, now.Time)
}

func (u *User) MarshalJSON() ([]byte, error) {
	if u == nil || u.User == nil {
		return []byte("null"), nil
	}
	values := u.User
	rUser := reflect.TypeOf(u).Elem()
	rUserVal := reflect.Indirect(reflect.ValueOf(u))
	for i := range rUser.NumField() {
		field := rUser.Field(i)
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			jsonTag, _, _ = strings.Cut(jsonTag, ",")
			values[jsonTag] = rUserVal.FieldByName(field.Name).Interface()
		}
	}
	return json.Marshal(values)
}
