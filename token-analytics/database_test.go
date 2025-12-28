// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExecOnRealMaster(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	const testLockName = "lock_name1"

	var wg sync.WaitGroup
	var syncCh = make(chan struct{}, 1)
	wg.Go(func() {
		syncCh <- struct{}{}
		r := execOnRealMasterWithLock(t.Context(), db, testLockName, "select pg_sleep(3)")
		require.NoError(t, r.Error)
		require.True(t, r.MasterExec, "should execute on master")
		require.True(t, r.LockAcquired, "should acquire lock")
	})

	time.Sleep(time.Second)
	<-syncCh // ensure the first goroutine started.
	r := execOnRealMasterWithLock(t.Context(), db, testLockName, "select 1")
	require.NoError(t, r.Error)
	require.True(t, r.MasterExec)
	require.False(t, r.LockAcquired)

	wg.Wait()
}
