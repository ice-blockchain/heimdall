// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/ddl"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/connectors/storage/v2/fixture"
)

var (
	testPgContainer *fixture.Container
)

func TestMain(m *testing.M) {
	ctx, cancel := context.WithCancel(context.Background())
	testPgContainer = fixture.New(ctx)
	code := m.Run()
	testPgContainer.Close(ctx)
	cancel()

	if code != 0 {
		os.Exit(code)
	}
}

func helperCreateDB(t *testing.T) (*storage.DB, func()) {
	t.Helper()

	connString, release := testPgContainer.MustTempDB(t.Context())
	db := storage.MustConnectWithCfg(t.Context(),
		&storage.Cfg{
			PrimaryURL:   connString,
			RunDDL:       true,
			IgnoreGlobal: true,
		},
		storage.NewFilesystemDDL(&ddl.Files, schemeMigrationTableName),
	)
	require.NotNil(t, db)

	return db, func() {
		db.Close()
		release()
	}
}

func TestStorageDDL(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	require.NoError(t, db.Ping(t.Context()))
}
