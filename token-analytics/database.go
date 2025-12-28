// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"net"

	"github.com/zeebo/xxh3"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

type execResult struct {
	RowsAffected uint64
	MasterExec   bool
	LockAcquired bool
	Error        error
}

func isOnMasterNow(ctx context.Context, db *storage.DB) (bool, error) {
	masterIPValue, err := storage.ExecOne[string](ctx, db, `select host(inet_server_addr())`)
	if err != nil {
		return false, fmt.Errorf("failed to get master DB IP address: %w", err)
	} else if masterIPValue == nil {
		return false, fmt.Errorf("master DB IP address is nil")
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("failed to get local IP addresses: %w", err)
	}

	var onMaster bool
	var masterIP = net.ParseIP(*masterIPValue)
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			onMaster = onMaster || ((masterIP.IsGlobalUnicast() && ipnet.IP.Equal(masterIP)) || ipnet.Contains(masterIP))
		}
	}
	return onMaster, nil
}

func execOnRealMasterWithLock(ctx context.Context, db *storage.DB, lockName, sql string, args ...any) execResult {
	onMaster, err := isOnMasterNow(ctx, db)
	if err != nil {
		return execResult{
			Error: fmt.Errorf("failed to determine if we are on master DB: %w", err),
		}
	}
	if !onMaster {
		log.Debug("skipping execution of SQL on master DB as we are not on master")
		return execResult{}
	}

	var userSqlRowsAffected uint64
	var lockAcquired bool
	err = storage.DoInTransaction(ctx, db, func(conn storage.QueryExecer) error {
		val, err := storage.ExecOne[bool](ctx, conn, `select pg_try_advisory_xact_lock($1)`, int64(xxh3.HashString(lockName)))
		if err != nil {
			return fmt.Errorf("failed to acquire advisory lock %v: %w", lockName, err)
		} else if val == nil || !*val {
			log.Debug(fmt.Sprintf("advisory lock %q is already held, skipping execution of SQL", lockName))
			return nil
		}

		lockAcquired = true
		userSqlRowsAffected, err = storage.Exec(ctx, conn, sql, args...)
		return err
	})

	return execResult{
		RowsAffected: userSqlRowsAffected,
		MasterExec:   true,
		LockAcquired: lockAcquired,
		Error:        err,
	}
}
