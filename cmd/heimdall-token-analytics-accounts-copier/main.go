// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

type (
	accountsDumper struct {
		accountsDB       *storage.DB
		tokenAnalyticsDB *storage.DB
	}

	userRecord struct {
		CreatedAt        *time.Time `db:"created_at"`
		UpdatedAt        *time.Time `db:"updated_at"`
		ID               string     `db:"id"`
		MasterPubkey     string     `db:"master_pubkey"`
		Username         string     `db:"username"`
		DisplayName      *string    `db:"display_name"`
		Avatar           *string    `db:"avatar"`
		Lookup           string     `db:"lookup"`
		IonConnectRelays []string   `db:"ion_connect_relays"`
		Verified         bool       `db:"verified"`
	}
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Received shutdown signal, stopping...")
		cancel()
	}()
	dumper := &accountsDumper{
		accountsDB:       storage.MustConnect(ctx, "", "accounts"),
		tokenAnalyticsDB: storage.MustConnect(ctx, "", "token-analytics"),
	}
	defer dumper.shutdown()

	log.Info("Starting accounts dumper...")
	if err := dumper.run(ctx); err != nil {
		log.Error(errors.Wrap(err, "accounts dumper failed"))

		os.Exit(1)
	}
	log.Info("Accounts dumper completed successfully")
}

func (d *accountsDumper) shutdown() {
	if err := d.accountsDB.Close(); err != nil {
		log.Error(errors.Wrap(err, "failed to close accounts DB"))
	}
	if err := d.tokenAnalyticsDB.Close(); err != nil {
		log.Error(errors.Wrap(err, "failed to close token analytics DB"))
	}
}

func (d *accountsDumper) run(ctx context.Context) error {
	lastSyncedAt, err := d.getLastSyncedTimestamp(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get last synced timestamp")
	}
	if lastSyncedAt == nil {
		log.Info("No previous sync found, starting from the beginning")
	} else {
		log.Info(fmt.Sprintf("Last sync: %v, fetching data after this timestamp", lastSyncedAt.String()))
	}

	batchSize := 5000
	offset := 0
	totalProcessed := 0
	for ctx.Err() == nil {
		users, err := d.fetchUsersBatch(ctx, lastSyncedAt, batchSize, offset)
		if err != nil {
			return errors.Wrapf(err, "failed to fetch users batch at offset %d", offset)
		}
		if len(users) == 0 {
			log.Info("No more users to process")

			break
		}
		inserted, err := d.insertUsers(ctx, users)
		if err != nil {
			return errors.Wrapf(err, "failed to insert users batch at offset %d", offset)
		}
		totalProcessed += inserted
		log.Info(fmt.Sprintf("Progress: processed %d users (batch: %d inserted, %d skipped)",
			totalProcessed, inserted, len(users)-inserted))

		if len(users) < batchSize {
			break
		}
		offset += batchSize
	}
	log.Info(fmt.Sprintf("Successfully processed %d users", totalProcessed))

	return nil
}

func (d *accountsDumper) getLastSyncedTimestamp(ctx context.Context) (*time.Time, error) {
	type result struct {
		MaxCreatedAt *time.Time `db:"max_created_at"`
	}
	sql := `SELECT MAX(created_at) as max_created_at FROM users`
	res, err := storage.Get[result](ctx, d.tokenAnalyticsDB, sql)
	if err != nil {
		return nil, nil
	}
	if res.MaxCreatedAt == nil {
		return nil, nil
	}

	return res.MaxCreatedAt, nil
}

func (d *accountsDumper) fetchUsersBatch(ctx context.Context, after *time.Time, limit, offset int) ([]*userRecord, error) {
	sql := `
		SELECT 
			sp.created_at,
			sp.updated_at,
			u.id,
			u.master_pubkey,
			sp.username,
			sp.display_name,
			sp.avatar,
			sp.lookup,
			u.ion_connect_relays,
			u.verified
		FROM social_profiles sp
		INNER JOIN users u ON u.master_pubkey = sp.master_pubkey`

	var args []any
	if after != nil {
		sql += `
		WHERE sp.created_at > $1
		ORDER BY sp.created_at ASC
		LIMIT $2 OFFSET $3`
		args = []any{after, limit, offset}
	} else {
		sql += `
		ORDER BY sp.created_at ASC
		LIMIT $1 OFFSET $2`
		args = []any{limit, offset}
	}
	users, err := storage.Select[userRecord](ctx, d.accountsDB, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to select users from accounts DB")
	}

	return users, nil
}

func (d *accountsDumper) insertUsers(ctx context.Context, users []*userRecord) (int, error) {
	if len(users) == 0 {
		return 0, nil
	}

	sql := `INSERT INTO users (
				created_at, updated_at, id, master_pubkey, username, 
				display_name, avatar, lookup, ion_connect_relays, verified
			) VALUES `

	var values []string
	var args []any
	paramIdx := 1

	for _, user := range users {
		values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			paramIdx, paramIdx+1, paramIdx+2, paramIdx+3, paramIdx+4,
			paramIdx+5, paramIdx+6, paramIdx+7, paramIdx+8, paramIdx+9))
		args = append(args,
			user.CreatedAt,
			user.UpdatedAt,
			user.ID,
			user.MasterPubkey,
			user.Username,
			user.DisplayName,
			user.Avatar,
			user.Lookup,
			user.IonConnectRelays,
			user.Verified,
		)
		paramIdx += 10
	}

	sql += strings.Join(values, ", ")
	sql += `
			ON CONFLICT (master_pubkey) DO UPDATE SET
				created_at = EXCLUDED.created_at,
				updated_at = EXCLUDED.updated_at,
				id = EXCLUDED.id,
				username = EXCLUDED.username,
				display_name = EXCLUDED.display_name,
				avatar = EXCLUDED.avatar,
				lookup = EXCLUDED.lookup,
				ion_connect_relays = EXCLUDED.ion_connect_relays,
				verified = EXCLUDED.verified`

	_, err := storage.Exec(ctx, d.tokenAnalyticsDB, sql, args...)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to insert batch of %d users", len(users))
	}

	return len(users), nil
}
