// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (a *accounts) UpsertDeeplink(ctx context.Context, eventAddress, deeplink string) error {
	sql := `INSERT INTO deeplinks (event_address, deeplink) 
	        VALUES ($1, $2) 
	        ON CONFLICT (event_address) 
	        DO UPDATE SET deeplink = EXCLUDED.deeplink`

	if _, err := storage.Exec(ctx, a.db, sql, eventAddress, deeplink); err != nil {
		return errors.Wrapf(err, "failed to upsert deeplink for event %s", eventAddress)
	}

	return nil
}
