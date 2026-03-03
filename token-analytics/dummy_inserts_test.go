// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateDummyDataFlow(t *testing.T) {
	t.Skip("not needed for now")
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ctx, cancel := context.WithCancel(t.Context())
		gen := dummyDataGenerator{
			Target:            db,
			InsertBlockIndex:  dummyDataLastBlock,
			IONTokenAddress:   "0x0000000000000000000000000000000000000001",
			MaxTokenGens:      60,
			MaxUsers:          10,
			TokenGeneratorTTL: time.Hour,
		}
		gen.Run(ctx)

		time.Sleep(time.Hour)
		synctest.Wait()
		require.InDelta(t, gen.MaxTokenGens, gen.activeTokensWorkers.Load(), 2)

		cancel()
	})
}
