// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (a *accounts) getUserByID(ctx context.Context, userID string) (*user, error) {
	u, err := storage.Get[user](ctx, a.db, `SELECT * FROM users where id = $1`, userID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user by ID %v")
	}
	return u, nil
}
