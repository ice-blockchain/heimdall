// SPDX-License-Identifier: ice License 1.0

package questdb

import (
	"context"
	_ "embed"
	"time"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/questdb/go-questdb-client/v4"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type (
	LineSender = questdb.LineSender
	Decimal    = questdb.Decimal
	Querier    interface {
		pgxscan.Querier
	}
	DB struct {
		db     *storage.DB
		writer *questdb.LineSenderPool
	}
	At interface {
		At(ctx context.Context, ts time.Time) error
	}
	WithTime interface {
		Time() time.Time
	}
	StructMarshaller interface {
		Marshal(client questdb.LineSender) At
		WithTime
	}
	ConnectionConfig struct {
		PostgresConn *storage.Cfg `yaml:"read" mapstructure:"read"`
		WriteURL     string       `yaml:"writeURL"`
		User         string       `yaml:"user"`
		Password     string       `yaml:"password"`
	}
)

type (
	config struct {
		QuestDB ConnectionConfig `yaml:"questdb" mapstructure:"questdb"`
	}
)

//go:embed DDL.sql
var DDL string
