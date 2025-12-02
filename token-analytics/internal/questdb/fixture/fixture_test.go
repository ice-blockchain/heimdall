// SPDX-License-Identifier: ice License 1.0

package fixture

import (
	"testing"

	"github.com/questdb/go-questdb-client/v4"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestCreateNewContainer(t *testing.T) {
	t.Parallel()

	c, err := New(t.Context())
	require.NoError(t, err)
	require.NotNil(t, c)

	t.Logf("QuestDB HTTP Address: %s", c.AddressHTTP)
	t.Logf("QuestDB PG Address:   %s", c.AddressPG)

	t.Run("connect to HTTP", func(t *testing.T) {
		client, err := questdb.PoolFromConf(c.AddressHTTP)
		require.NoError(t, err)
		require.NotNil(t, client)

		sender, err := client.Sender(t.Context())
		require.NoError(t, err)
		require.NotNil(t, sender)

		require.NoError(t, sender.Flush(t.Context()))
		require.NoError(t, sender.Close(t.Context()))
		require.NoError(t, client.Close(t.Context()))
	})

	t.Run("connect to PG", func(t *testing.T) {
		db := storage.MustConnectWithCfg(
			t.Context(),
			&storage.Cfg{
				PrimaryURL:               c.AddressPG,
				SkipSettingsVerification: true,
				ReplicaURLs: []string{
					c.AddressPG,
				},
			},
			nil,
		)
		require.NotNil(t, db)
		t.Log("connected to PG")

		require.NoError(t, db.Ping(t.Context(), storage.PingWithoutWriteCheck()))
		require.NoError(t, db.Close())
	})

	c.Terminate(t.Context())
}
