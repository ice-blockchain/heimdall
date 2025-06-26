// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (a *accounts) registrationsEnabled() (enabled, earlyAccess bool, err error) {
	return a.appsRuntimeConfig.IONApp.AllowNewRegistrations, a.appsRuntimeConfig.IONApp.EnableEarlyAccessRegistrations, nil
}

func (a *accounts) isEmailAllowed(ctx context.Context, email string, userID *string) error {
	maxAllowedPerEmail := a.appsRuntimeConfig.IONApp.MaxEarlyAccessRegistrationsAllowedPerEmail
	upsertUserID := ""
	email = strings.ToLower(email)
	params := []any{email, maxAllowedPerEmail}
	if userID != nil {
		upsertUserID = `WITH upsert_user AS (
			INSERT INTO assigned_early_access_emails(email, user_id) VALUES ($1, $3)
		)`
		params = append(params, *userID)
	}
	allowed, err := storage.ExecOne[struct {
		EmailAllowed bool `db:"email_allowed"`
	}](ctx, a.db, fmt.Sprintf(`
			%v
			SELECT (exists(SELECT 1 FROM early_access_emails WHERE email = $1) 
			           and (SELECT count(*) FROM assigned_early_access_emails WHERE email = $1) < $2) as email_allowed;`, upsertUserID), params...)
	if err != nil {
		return errors.Wrapf(err, "failed to check if email %v is allowed", email)
	}
	if !allowed.EmailAllowed {
		return ErrEmailNotAllowedForEarlyAccess
	}
	return nil
}

func (a *accounts) verifyEarlyAccessAndUpsertUserID(ctx context.Context, email string, res map[string]any) error {
	userID, _ := dfns.ExtractUser(res, "username")
	return a.VerifyEarlyAccess(ctx, email, &userID)
}

func (a *accounts) VerifyEarlyAccess(ctx context.Context, email string, userID *string) error {
	registrationsEnabled, earlyAccess, rErr := a.registrationsEnabled()
	if rErr != nil {
		return errors.Wrapf(rErr, "failed to check if registrations are enabled")
	}
	if !registrationsEnabled {
		return ErrRegistrationsDisabled
	}
	if earlyAccess {
		if err := a.isEmailAllowed(ctx, email, userID); err != nil {
			return err
		}
	}
	return nil
}
