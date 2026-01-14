// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ice-blockchain/wintr/log"
)

const (
	dragonflyImage = "docker.dragonflydb.io/dragonflydb/dragonfly:latest"
)

var (
	testRedis *redis.Client
)

type testRedisDB struct {
	*redis.Client
}

func (t *testRedisDB) IsRW(_ context.Context) bool {
	return true
}

func mustStartDragonflyContainer(ctx context.Context) (testcontainers.Container, string, func()) {
	req := testcontainers.ContainerRequest{
		Image:        dragonflyImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp"),
		Cmd:          []string{"--maxmemory", "512mb", "--proactor_threads", "2"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		log.Panic(errors.Wrap(err, "failed to start dragonfly container"))
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		log.Panic(errors.Wrap(err, "failed to get dragonfly host"))
	}
	mappedPort, err := container.MappedPort(ctx, "6379")
	if err != nil {
		_ = container.Terminate(ctx)
		log.Error(errors.Wrap(err, "failed to get dragonfly mapped port"))
	}

	addr := "redis://" + host + ":" + mappedPort.Port()
	release := func() {
		_ = container.Terminate(ctx)
	}

	return container, addr, release
}

func mustConnectDragonfly(ctx context.Context, addr string) *redis.Client {
	opt, err := redis.ParseURL(addr)
	if err != nil {
		log.Panic(errors.Wrap(err, "failed to parse dragonfly url"))
	}

	client := redis.NewClient(opt)
	if err := client.Ping(ctx).Err(); err != nil {
		log.Panic(errors.Wrap(err, "failed to ping dragonfly"))
	}

	return client
}
