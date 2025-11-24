// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	_ "embed"
	"flag"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/heimdall/token-analytics/fixture"
	// "github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

var (
	testContainers *fixture.TestContainers
	testDB         *storage.DB
	testRedis      *testRedisWrapper
	// testQuestDB    *questdb.DB
	testCleanup func()

	//go:embed DDL.sql
	testDDL string
	// //go:embed fixture/questdb_test_ddl.sql
	// testQuestDBDDL string
)

type testRedisWrapper struct {
	*redis.Client
}

func (w *testRedisWrapper) Close() error {
	return w.Client.Close()
}

func (w *testRedisWrapper) IsRW(ctx context.Context) bool {
	return true
}

func (w *testRedisWrapper) Unwrap() *redis.Client {
	return w.Client
}

func TestMain(m *testing.M) {
	flag.Parse()

	ctx := context.Background()
	var err error
	testContainers, testCleanup, err = fixture.SetupTestContainers(ctx)
	if err != nil {
		panic("failed to setup test containers: " + err.Error())
	}
	testDB, err = testContainers.ConnectPostgreSQL(ctx, testDDL, true)
	if err != nil {
		testCleanup()
		panic("failed to connect to postgres: " + err.Error())
	}
	redisClient, err := testContainers.ConnectDragonfly(ctx)
	if err != nil {
		testCleanup()
		panic("failed to connect to dragonfly: " + err.Error())
	}
	testRedis = &testRedisWrapper{Client: redisClient}

	// TODO: Connect to QuestDB later
	// testQuestDB, err = testContainers.ConnectQuestDB(ctx, testQuestDBDDL)
	// if err != nil {
	// 	testCleanup()
	// 	panic("failed to connect to questdb: " + err.Error())
	// }

	exitCode := m.Run()

	cleanupAllTestData(ctx)
	if testRedis != nil {
		_ = testRedis.Close()
	}
	if testDB != nil {
		_ = testDB.Close()
	}
	// if testQuestDB != nil {
	// 	_ = testQuestDB.Close(ctx)
	// }
	if testCleanup != nil {
		testCleanup()
	}

	os.Exit(exitCode)
}

func cleanupAllTestData(ctx context.Context) {
	tables := []string{
		"user_token_positions",
		"token_swaps",
		"tokens",
		"users",
		"tx_logs",
		"transactions",
		"smart_contract_transactions",
		"streams",
		"global_settings",
	}

	if err := testContainers.TruncatePostgresTables(ctx, testDB, tables...); err != nil {
		println("Warning: failed to truncate PostgreSQL tables:", err.Error())
	}
	if err := testContainers.FlushDragonfly(ctx, testRedis.Unwrap()); err != nil {
		println("Warning: failed to flush Dragonfly:", err.Error())
	}

	// TODO: Clean QuestDB later
	// testIntervals := []string{"1m", "5m"}
	// for _, interval := range testIntervals {
	// 	tableName := "ohlcv_" + interval
	// 	query := "TRUNCATE TABLE " + tableName
	// 	if _, err := questdb.Exec(ctx, testQuestDB, query); err != nil {
	// 		println("Warning: failed to truncate", tableName+":", err.Error())
	// 	}
	// }
}
