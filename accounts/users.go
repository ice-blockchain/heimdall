// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (a *accounts) getUserByID(ctx context.Context, userID string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT * FROM users where id = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by ID %v", userID)
	}
	return u, nil
}
func (a *accounts) getUserByUsername(ctx context.Context, username string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT * FROM users where dfns_username = $1`, username)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by username %v", username)
	}
	return u, nil
}
func clientIPAddress(ctx context.Context) string {
	return ctx.Value(clientIPCtxValueKey).(string)
}
func (a *accounts) GetIONRelays(ctx context.Context, userID string, followees []string) (relays []string, err error) {
	usr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to check if user already have ion relays")
	}
	if len(usr.IONRelays) > 0 {
		return usr.IONRelays, nil
	}
	return a.fetchAndUpdateRelaysFromPolaris(ctx, userID, followees)
}
func (a *accounts) GetIONIndexers(ctx context.Context, userID string) (indexers []string, err error) {
	return a.fetchIONIndexers(ctx, userID)
}

func (a *accounts) fetchAndUpdateRelaysFromPolaris(ctx context.Context, userID string, followees []string) (relays []string, err error) {
	if relays, err = a.fetchRelays(ctx, userID, followees); err != nil {
		return nil, errors.Wrapf(err, "cannot fetch relay list from polaris")
	}
	if len(relays) > 0 {
		var usr *user
		usr, err = storage.ExecOne[user](ctx, a.db, `
					INSERT INTO 
    					users (id, ion_relays, dfns_username) VALUES ($1, $2, $1) 
    				ON CONFLICT(id) DO UPDATE 
    					SET ion_relays = $2
    				WHERE users.ion_relays IS NULL RETURNING *`, userID, relays)
		if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
			return nil, errors.Wrapf(err, "failed to persist ion relays for userID %v", userID)
		}
		if usr == nil {
			usr, err = a.getUserByID(ctx, userID)
			if err != nil {
				return nil, errors.Wrapf(err, "race condition but cannot get user for userID %v:", userID)
			}
		}

		return usr.IONRelays, nil
	}

	return relays, nil
}

func (a *accounts) fetchRelays(ctx context.Context, userID string, followeeList []string) (relays []string, err error) {
	log.Info("Fetching relay from polaris for %v", clientIPAddress(ctx))
	return []string{"ws://example1.com/", "wss://example2.com/", "ws://example3.com/ws"}, nil
}
func (a *accounts) fetchIONIndexers(ctx context.Context, userID string) (relays []string, err error) {
	log.Info("Fetching indexers from polaris for %v", clientIPAddress(ctx))
	return []string{"https://indexer-example1.com/", "https://indexer-example2.com/", "https://indexer-example3.com/ws"}, nil
}

func (a *accounts) GetUser(ctx context.Context, userID string) (*User, error) {
	dbUsr, err := a.getUserByID(ctx, userID)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to read extra information about user %v", userID)
	}
	dfnsUsr, err := a.dfnsClient.GetUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user from dfns for ID %v", userID)
	}
	usr := &User{User: dfnsUsr}
	if dbUsr != nil {
		usr.IONRelays = dbUsr.IONRelays
		usr.IONIndexers, err = a.GetIONIndexers(ctx, userID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch indexers for userID %v", userID)
		}
		twoFAOptions := make([]TwoFAOptionEnum, 0, len(AllTwoFAOptions))
		if dbUsr.Email != nil && *dbUsr.Email != "" {
			twoFAOptions = append(twoFAOptions, TwoFAOptionEmail)
			usr.Email = *dbUsr.Email

		}
		if dbUsr.PhoneNumber != nil && *dbUsr.PhoneNumber != "" {
			twoFAOptions = append(twoFAOptions, TwoFAOptionSMS)
			usr.PhoneNumber = *dbUsr.PhoneNumber
		}
		if dbUsr.TotpAuthentificatorSecret != nil && *dbUsr.TotpAuthentificatorSecret != "" {
			twoFAOptions = append(twoFAOptions, TwoFAOptionTOTPAuthentificator)
		}
	}
	return usr, nil
}
func (a *accounts) insertUserWithUsername(ctx context.Context, userID, dfnsUsername string) error {
	_, err := storage.Exec(ctx, a.db, `INSERT INTO users(id, dfns_username) VALUES ($1,$2) ON CONFLICT(id) DO UPDATE 
    										SET dfns_username = $2 WHERE users.dfns_username = '' OR users.dfns_username = users.id`, userID, dfnsUsername)
	return errors.Wrapf(err, "failed to update user with username in db %v %v", userID, dfnsUsername)

}
