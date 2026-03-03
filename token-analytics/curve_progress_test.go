// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetBondingCurveProgress(t *testing.T) {
	t.Parallel()
	t.Run("returns bonding curve progress from RPC", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		tokenExternalAddr := "0:test_token_progress:"
		pairID := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8" // ION
		contractAddr := "0x1234567890123456789012345678901234567890"

		helperInsertTestToken(t, t.Context(), db,
			contractAddr, tokenExternalAddr, "TEST", "profile", "test_master",
			"1000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, t.Context(), db, tokenExternalAddr, pairID, baseToken)

		helperInsertBaseTokenPrice(t, t.Context(), db, baseToken, "ION", 0.01)
		progress, err := ta.GetBondingCurveProgress(t.Context(), tokenExternalAddr)

		require.NoError(t, err)
		require.NotNil(t, progress)
		require.Equal(t, "100000000000000000000", progress.CurrentAmount) // 100 tokens from mock
		require.Equal(t, "200000000000000000000", progress.GoalAmount)    // 200 tokens from mock
		require.Equal(t, "10000000000000000000", progress.RaisedAmount)   // 10 base tokens from mock
		require.False(t, progress.Migrated)
		require.Greater(t, progress.CurrentAmountUSD, 0.0)
		require.Greater(t, progress.GoalAmountUSD, 0.0)
	})

	t.Run("returns error when token not found", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		progress, err := ta.GetBondingCurveProgress(t.Context(), "0:non_existent_token:")

		require.Error(t, err)
		require.Nil(t, progress)
	})

	t.Run("returns error when pair_id is missing", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:test_token_no_pair:"
		contractAddr := "0x2234567890123456789012345678901234567890"

		helperInsertTestToken(t, t.Context(), db,
			contractAddr, tokenExternalAddr, "TEST", "profile", "test_master",
			"1000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		progress, err := ta.GetBondingCurveProgress(t.Context(), tokenExternalAddr)

		require.Error(t, err)
		require.Nil(t, progress)
	})
}

func TestSubscribeBondingCurveProgress(t *testing.T) {
	t.Parallel()
	t.Run("sends initial progress", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:test_token_subscribe:"
		pairID := "0x3234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"
		contractAddr := "0x3234567890123456789012345678901234567890"

		helperInsertTestToken(t, t.Context(), db,
			contractAddr, tokenExternalAddr, "TEST", "profile", "test_master",
			"1000000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, t.Context(), db, tokenExternalAddr, pairID, baseToken)
		helperInsertBaseTokenPrice(t, t.Context(), db, baseToken, "ION", 0.01)

		var receivedProgress *BondingCurveProgress
		done := make(chan struct{})

		addToStream := func(progress *BondingCurveProgress, err error) {
			if receivedProgress == nil {
				require.NoError(t, err)
				receivedProgress = progress
				close(done)
			}
		}

		err := ta.SubscribeBondingCurveProgress(t.Context(), tokenExternalAddr, "bogus", addToStream)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for initial update")
		}

		require.NotNil(t, receivedProgress)
		require.Equal(t, "100000000000000000000", receivedProgress.CurrentAmount)
		require.Equal(t, "200000000000000000000", receivedProgress.GoalAmount)
	})

	t.Run("returns error when token not found", func(t *testing.T) {
		ctx := context.Background()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		addToStream := func(progress *BondingCurveProgress, err error) {
			t.Fatal("should not be called")
		}

		err := ta.SubscribeBondingCurveProgress(ctx, "0:non_existent:", "bogus", addToStream)
		require.Error(t, err)
	})
}
