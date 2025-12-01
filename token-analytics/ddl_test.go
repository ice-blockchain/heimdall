// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/ddl"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/connectors/storage/v2/fixture"
)

func TestStorageDDL(t *testing.T) {
	t.Parallel()

	container := fixture.New(t.Context())
	connString, release := container.MustTempDB(t.Context())

	db := storage.MustConnectWithCfg(t.Context(),
		&storage.Cfg{
			PrimaryURL:   connString,
			RunDDL:       true,
			IgnoreGlobal: true,
		},
		storage.NewFilesystemDDL(&ddl.Files, schemeMigrationTableName),
	)
	require.NotNil(t, db)

	require.NoError(t, db.Ping(t.Context()))
	db.Close()
	release()
	container.Close(t.Context())
}
