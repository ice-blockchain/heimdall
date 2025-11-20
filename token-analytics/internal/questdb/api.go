// SPDX-License-Identifier: ice License 1.0

package questdb

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5"
	"github.com/questdb/go-questdb-client/v4"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (c *DB) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return c.db.Query(ctx, query, args...)
}

func (c *DB) Close(ctx context.Context) error {
	return errors.Join(
		errors.Wrapf(c.db.Close(), "failed to close questdb postgres conn"),
		errors.Wrapf(c.writer.Close(ctx), "failed to close questdb influx conn"),
	)
}

func MustConnect(ctx context.Context, applicationYamlKey string) *DB {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if !strings.Contains(cfg.QuestDB.WriteURL, "username=") {
		cfg.QuestDB.WriteURL += fmt.Sprintf(";username=%v", cfg.QuestDB.User)
	}
	if !strings.Contains(cfg.QuestDB.WriteURL, "password=") {
		cfg.QuestDB.WriteURL += fmt.Sprintf(";password=%v", cfg.QuestDB.Password)
	}
	questdbConn, err := questdb.PoolFromConf(cfg.QuestDB.WriteURL)
	if err != nil {
		log.Panic(errors.Wrapf(err, "failed to connect questdb (influx)"))
	}
	pgxConn := storage.MustConnectWithCfg(ctx, cfg.QuestDB.PostgresConn, ddl)
	return &DB{
		db:     pgxConn,
		writer: questdbConn,
	}
}

func Write[T StructMarshaller](ctx context.Context, client *DB, items ...T) (err error) {
	sender, err := client.writer.Sender(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to allocate sender from quest db pool")
	}
	defer func() {
		clerr := errors.Wrapf(sender.Close(ctx), "failed to close sender back to pool")
		if err == nil && clerr != nil {
			err = clerr
		}
	}()
	for i := range items {
		err = errors.Join(errors.Wrapf(items[i].Marshal(sender).At(ctx, items[i].Time()), "failed to serialize %+v", items[i]))
	}
	return errors.Wrapf(sender.Flush(ctx), "flush failed")
}

func Get[T any](ctx context.Context, db Querier, sql string, args ...any) (*T, error) {
	return storage.Get[T](ctx, db, sql, args)
}

func Select[T any](ctx context.Context, db Querier, sql string, args ...any) ([]*T, error) {
	return storage.Select[T](ctx, db, sql, args)
}

func NewDecimal(bi *big.Int) Decimal {
	dec, err := questdb.NewDecimal(bi, 0)
	if err != nil {
		log.Panic(errors.Wrapf(err, "decimal %v exceeding 256 bits", bi.String()))
	}
	return dec
}
