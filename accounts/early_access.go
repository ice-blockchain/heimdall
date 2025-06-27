// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (a *accounts) registrationsEnabled() (enabled, earlyAccess bool, err error) {
	return a.appsRuntimeConfig.IONApp.AllowNewRegistrations, a.appsRuntimeConfig.IONApp.EnableEarlyAccessRegistrations, nil
}

func (a *accounts) isEmailAllowed(ctx context.Context, email string) error {
	maxAllowedPerEmail := a.appsRuntimeConfig.IONApp.MaxEarlyAccessRegistrationsAllowedPerEmail
	sql := `SELECT (exists(SELECT 1 FROM early_access_emails WHERE email = $1) 
			           and (SELECT count(*) FROM assigned_early_access_emails WHERE email = $1) < $2) as email_allowed;`
	email = strings.ToLower(email)
	params := []any{email, maxAllowedPerEmail}
	allowed, err := storage.ExecOne[struct {
		EmailAllowed bool `db:"email_allowed"`
	}](ctx, a.db, sql, params...)
	if err != nil {
		return errors.Wrapf(err, "failed to check if email %v is allowed", email)
	}
	if !allowed.EmailAllowed {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	return nil
}

func (a *accounts) markEmailAsUsed(ctx context.Context, email string, userID string) error {
	maxAllowedPerEmail := a.appsRuntimeConfig.IONApp.MaxEarlyAccessRegistrationsAllowedPerEmail
	sql := `WITH inserted_users AS (
			WITH allowed_email AS (
				SELECT * FROM (VALUES($1, $3)) as t(email, user_id) WHERE (SELECT count(*) FROM assigned_early_access_emails WHERE email = $1) < $2
			)
			INSERT INTO assigned_early_access_emails(email, user_id) SELECT email, user_id FROM allowed_email ON CONFLICT(email, user_id) DO NOTHING
			RETURNING 1) SELECT count(*) > 0 AS email_allowed from inserted_users`
	email = strings.ToLower(email)
	params := []any{email, maxAllowedPerEmail, userID}
	allowed, err := storage.ExecOne[struct {
		EmailAllowed bool `db:"email_allowed"`
	}](ctx, a.db, sql, params...)
	if err != nil {
		if storage.IsErr(err, storage.ErrRelationNotFound) {
			err = nil
			allowed = &struct {
				EmailAllowed bool `db:"email_allowed"`
			}{EmailAllowed: false}
		}
		return errors.Wrapf(err, "failed to check if email %v is allowed and insert user ID %v", email, userID)
	}
	if !allowed.EmailAllowed {
		derr := new(dfns.DfnsInternalError)
		*derr = *ErrEmailNotAllowedForEarlyAccess
		derr.HTTPStatus = http.StatusForbidden
		return derr
	}
	return nil

}

func (a *accounts) verifyEarlyAccessAndUpsertUserID(ctx context.Context, email string, res map[string]any) error {
	userID, _ := dfns.ExtractUser(res, "username")
	return a.markEmailAsUsed(ctx, email, userID)
}

func (a *accounts) VerifyEarlyAccess(ctx context.Context, email string) error {
	registrationsEnabled, earlyAccess, rErr := a.registrationsEnabled()
	if rErr != nil {
		return errors.Wrapf(rErr, "failed to check if registrations are enabled")
	}
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
