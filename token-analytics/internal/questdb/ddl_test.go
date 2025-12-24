// SPDX-License-Identifier: ice License 1.0

package questdb

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb/fixture"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestApplyDDL(t *testing.T) {
	t.Parallel()

	c, err := fixture.New(t.Context())
	require.NoError(t, err)
	require.NotNil(t, c)

	client := mustConnectWithConfig(t.Context(), &config{
		QuestDB: ConnectionConfig{
			WriteURL: c.AddressHTTP,
			PostgresConn: &storage.Cfg{
				PrimaryURL: c.AddressPG,
				RunDDL:     true,
			},
		},
	})
	require.NotNil(t, client)

	require.NoError(t, client.Ping(t.Context()))
	require.NoError(t, client.Close(t.Context()))
	require.NoError(t, c.Terminate(t.Context()))
}
