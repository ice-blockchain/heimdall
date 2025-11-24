// SPDX-License-Identifier: ice License 1.0

package fixture

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

const (
	postgresUser     = "root"
	postgresPassword = "pass"
	postgresDB       = "heimdall"

	dragonflyImage = "docker.dragonflydb.io/dragonflydb/dragonfly:latest"
	questdbImage   = "questdb/questdb:latest"
)

type (
	TestContainers struct {
		PostgreSQL *postgres.PostgresContainer
		Dragonfly  testcontainers.Container
		QuestDB    testcontainers.Container

		PostgresConnStr  string
		DragonflyAddr    string
		QuestDBHTTPAddr  string
		QuestDBPGAddr    string
		QuestDBWriteAddr string // ILP (InfluxDB Line Protocol) address
	}

	Cleanup func()
)

func SetupTestContainers(ctx context.Context) (*TestContainers, Cleanup, error) {
	tc := &TestContainers{}
	cleanups := make([]func(), 0, 3)

	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	pgContainer, err := postgres.Run(ctx,
		"postgres:17.5-alpine",
		postgres.WithDatabase(postgresDB),
		postgres.WithUsername(postgresUser),
		postgres.WithPassword(postgresPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to start postgres container: %w", err)
	}
	tc.PostgreSQL = pgContainer
	cleanups = append(cleanups, func() {
		_ = pgContainer.Terminate(ctx)
	})

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to get postgres connection string: %w", err)
	}
	tc.PostgresConnStr = connStr

	dragonflyContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        dragonflyImage,
			ExposedPorts: []string{"6379/tcp"},
			Cmd:          []string{"--proactor_threads=2", "--maxmemory=512mb"},
			WaitingFor: wait.ForListeningPort("6379/tcp").
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to start dragonfly container: %w", err)
	}
	tc.Dragonfly = dragonflyContainer
	cleanups = append(cleanups, func() {
		_ = dragonflyContainer.Terminate(ctx)
	})

	dragonflyHost, err := dragonflyContainer.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to get dragonfly host: %w", err)
	}
	dragonflyPort, err := dragonflyContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to get dragonfly port: %w", err)
	}
	tc.DragonflyAddr = fmt.Sprintf("redis://%s:%s", dragonflyHost, dragonflyPort.Port())

	questdbContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        questdbImage,
			ExposedPorts: []string{"9000/tcp", "8812/tcp", "9009/tcp"},
			Env: map[string]string{
				"QDB_TELEMETRY_ENABLED": "false",
			},
			WaitingFor: wait.ForLog("server is ready").
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to start questdb container: %w", err)
	}
	tc.QuestDB = questdbContainer
	cleanups = append(cleanups, func() {
		_ = questdbContainer.Terminate(ctx)
	})

	questdbHTTPHost, err := questdbContainer.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to get questdb host: %w", err)
	}
	questdbHTTPPort, err := questdbContainer.MappedPort(ctx, "9000")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to get questdb http port: %w", err)
	}
	tc.QuestDBHTTPAddr = fmt.Sprintf("http://%s:%s", questdbHTTPHost, questdbHTTPPort.Port())

	questdbPGPort, err := questdbContainer.MappedPort(ctx, "8812")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to get questdb pg port: %w", err)
	}
	tc.QuestDBPGAddr = fmt.Sprintf("host=%s port=%s user=admin password=quest dbname=qdb sslmode=disable",
		questdbHTTPHost, questdbPGPort.Port())

	tc.QuestDBWriteAddr = fmt.Sprintf("http::addr=%s:%s", questdbHTTPHost, questdbHTTPPort.Port())

	return tc, cleanup, nil
}

func (tc *TestContainers) ConnectPostgreSQL(ctx context.Context, ddl string, runDDL bool) (*storage.DB, error) {
	cfg := &storage.Cfg{
		PrimaryURL:               tc.PostgresConnStr,
		ReplicaURLs:              []string{tc.PostgresConnStr}, // Use primary as replica to avoid divide by zero
		RunDDL:                   runDDL,
		SkipSettingsVerification: true,
	}
	cfg.Credentials.User = postgresUser
	cfg.Credentials.Password = postgresPassword

	db := storage.MustConnectWithCfg(ctx, cfg, ddl)
	return db, nil
}

func (tc *TestContainers) ConnectDragonfly(ctx context.Context) (*redis.Client, error) {
	opt, err := redis.ParseURL(tc.DragonflyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dragonfly url: %w", err)
	}

	client := redis.NewClient(opt)
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping dragonfly: %w", err)
	}

	return client, nil
}

// func (tc *TestContainers) ConnectQuestDB(ctx context.Context, ddl string, runDDL bool) (*storage.DB, *questdbclient.LineSenderPool, error) {
// 	cfg := &storage.Cfg{
// 		PrimaryURL:               tc.QuestDBPGAddr,
// 		ReplicaURLs:              []string{tc.QuestDBPGAddr},
// 		RunDDL:                   runDDL,
// 		SkipSettingsVerification: true,
// 	}
// 	cfg.Credentials.User = "admin"
// 	cfg.Credentials.Password = "quest"
// 	pgDB := storage.MustConnectWithCfg(ctx, cfg, ddl)

// 	confStr := tc.QuestDBWriteAddr + ";"
// 	ilpPool, err := questdbclient.PoolFromConf(confStr)
// 	if err != nil {
// 		_ = pgDB.Close()
// 		return nil, nil, fmt.Errorf("failed to create questdb ILP pool: %w", err)
// 	}

// 	return pgDB, ilpPool, nil
// }

func (tc *TestContainers) FlushDragonfly(ctx context.Context, client *redis.Client) error {
	return client.FlushAll(ctx).Err()
}

func (tc *TestContainers) TruncatePostgresTables(ctx context.Context, db *storage.DB, tables ...string) error {
	for _, table := range tables {
		query := fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)
		if _, err := storage.Exec(ctx, db, query); err != nil {
			return fmt.Errorf("failed to truncate table %s: %w", table, err)
		}
	}
	return nil
}

func SkipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
}

func SetupTest(t *testing.T, ctx context.Context, ddl string, runDDL bool) (*TestContainers, *storage.DB, *redis.Client, func()) {
	t.Helper()
	SkipIfShort(t)

	containers, cleanup, err := SetupTestContainers(ctx)
	require.NoError(t, err, "failed to setup test containers")

	pgDB, err := containers.ConnectPostgreSQL(ctx, ddl, runDDL)
	require.NoError(t, err, "failed to connect to postgres")

	redisClient, err := containers.ConnectDragonfly(ctx)
	require.NoError(t, err, "failed to connect to dragonfly")

	cleanupFunc := func() {
		if redisClient != nil {
			_ = redisClient.Close()
		}
		if pgDB != nil {
			_ = pgDB.Close()
		}
		cleanup()
	}

	return containers, pgDB, redisClient, cleanupFunc
}

func WaitForCondition(t *testing.T, ctx context.Context, timeout time.Duration, interval time.Duration, condition func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled while waiting: %s", message)
		case <-time.After(interval):
			// continue
		}
	}
	t.Fatalf("timeout waiting for condition: %s", message)
}
