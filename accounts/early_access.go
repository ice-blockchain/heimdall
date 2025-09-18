// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func (a *accounts) registrationsEnabled() (enabled, earlyAccess bool) {
	return a.appsRuntimeConfig.IONApp.AllowNewRegistrations, a.appsRuntimeConfig.IONApp.EnableEarlyAccessRegistrations
}

func (a *accounts) isEmailAllowed(ctx context.Context, email string) error {
	if strings.TrimSpace(email) == "" {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	maxAllowedPerEmail := a.appsRuntimeConfig.IONApp.MaxEarlyAccessRegistrationsAllowedPerEmail
	sql := `SELECT exists(SELECT 1 FROM early_access_emails WHERE email = $1) as email_allowed,
       ((SELECT count(*) FROM assigned_early_access_emails WHERE email = $1) < $2) as email_not_used;`
	email = strings.TrimSpace(strings.ToLower(email))
	params := []any{email, maxAllowedPerEmail}
	allowed, err := storage.ExecOne[struct {
		EmailAllowed bool `db:"email_allowed"`
		EmailNotUsed bool `db:"email_not_used"`
	}](ctx, a.db, sql, params...)
	if err != nil {
		return errors.Wrapf(err, "failed to check if email %v is allowed", email)
	}
	if !allowed.EmailNotUsed {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailUsed
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	if !allowed.EmailAllowed {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	return nil
}

func (a *accounts) insertRegistrationComplete(ctx context.Context, now *time.Time, email, userID, identityKeyName, deviceIdentificationRequestId string) error {
	maxAllowedPerEmail := a.appsRuntimeConfig.IONApp.MaxEarlyAccessRegistrationsAllowedPerEmail
	email = strings.ToLower(email)
	params := []any{email, maxAllowedPerEmail, userID}
	visitorInsert := ""
	if deviceIdentificationRequestId != "" {
		visitorInsert = `visitor_insert AS (
		INSERT INTO users_visitors(created_at, user_id, visitor_id, device_pubkey) VALUES ($4, $3, $3, $3)
		ON CONFLICT(user_id, visitor_id) DO NOTHING
	),`
		params = append(params, *now.Time)
	}
	sql := fmt.Sprintf(`WITH %v
				allowed_email AS (
					SELECT * FROM (VALUES($1, $3)) as t(email, user_id) WHERE (SELECT count(*) FROM assigned_early_access_emails WHERE email = $1) <= $2
				)
				SELECT ae.user_id, ae.email, assigned.email as key_name FROM allowed_email ae
				JOIN assigned_early_access_emails assigned ON ae.user_id = assigned.user_id`, visitorInsert)
	res, err := storage.ExecOne[struct {
		UserID          string `db:"user_id"`
		Email           string `db:"email"`
		IdentityKeyName string `db:"key_name"`
	}](ctx, a.db, sql, params...)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			derr := new(dfns.DfnsInternalError)
			*derr = *ErrEmailNotAllowedForEarlyAccess
			derr.HTTPStatus = http.StatusForbidden
			return derr
		}
		return errors.Wrapf(err, "failed to insert registration complete")
	}
	if res == nil {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	if res.Email != email || res.IdentityKeyName != identityKeyName || res.UserID != userID {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	return nil

}

func (a *accounts) VerifyEarlyAccess(ctx context.Context, email string) error {
	registrationsEnabled, earlyAccess := a.registrationsEnabled()
	if !registrationsEnabled {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrRegistrationsDisabled
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	if earlyAccess {
		if err := a.isEmailAllowed(ctx, email); err != nil {
			return err
		}
	}
	return nil
}
