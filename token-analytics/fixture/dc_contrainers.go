package fixture

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ice-blockchain/wintr/log"
)

func NewFixture(ctx context.Context) (*TestContainers, Cleanup, error) {
	t := &TestContainers{}
	dockerCompose, err := compose.NewDockerComposeWith(
		compose.WithLogger(t),
		compose.WithStackFiles(locateDockerCompose()...),
	)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to init docker compose %+v", locateDockerCompose())
	}
	if err = dockerCompose.Up(ctx); err != nil {
		return nil, nil, errors.Wrap(err, "failed to start docker compose")
	}
	dockerCompose.WaitForService("postgres", wait.ForLog("database system is ready to accept connections").
		WithOccurrence(2).
		WithStartupTimeout(60*time.Second),
	)

	t.dockerCompose = dockerCompose
	questDbHttpPort, err := t.getContainerPort(ctx, "questdb", "9000/tcp")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get questdb write port")
	}
	questDbPgPort, err := t.getContainerPort(ctx, "questdb", "8812/tcp")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get questdb pg port")
	}
	t.QuestDBWriteAddr = fmt.Sprintf("http::addr=localhost:%v", questDbHttpPort)
	t.QuestDBPGAddr = fmt.Sprintf("postgresql://root:pass@localhost:%v/qdb?ssl_mode=disable", questDbPgPort)
	dflyPort, err := t.getContainerPort(ctx, "dragonflydb", "6379/tcp")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get dragonfly port")
	}
	t.DragonflyAddr = fmt.Sprintf("redis://default:@localhost:%v", dflyPort)
	pgPort, err := t.getContainerPort(ctx, "postgres", "5432/tcp")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get postgres port")
	}
	t.PostgresConnStr = fmt.Sprintf("postgresql://root:pass@localhost:%v/ingested_data", pgPort)
	return t, func() {
		t.dockerCompose.Down(ctx)
	}, nil
}

func (t *TestContainers) Printf(format string, v ...any) {
	fmt.Printf(format+"\n", v...)
}

func (t *TestContainers) getContainerPort(ctx context.Context, service string, port string) (string, error) {
	container, err := t.dockerCompose.ServiceContainer(ctx, service)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get container for service %v", service)
	}
	inspect, err := container.Inspect(ctx)
	if err != nil {
		return "", errors.Wrapf(err, "failed to inspect container for service %v", service)
	}
	ports := inspect.NetworkSettings.Ports[nat.Port(port)]
	if len(ports) == 0 {
		return "", errors.Errorf("failed to get port for service %v", service)
	}
	return ports[0].HostPort, nil
}

func locateDockerCompose() []string {
	var files []string
	var hints []string

	if p, err := os.Getwd(); err == nil {
		hints = append(hints, p)
	}
	if p, err := os.Executable(); err == nil {
		hints = append(hints, path.Dir(filepath.Join(p, "..")))
	}

	for _, dir := range hints {
		pattern := filepath.Join(dir, ".testdata", "docker-compose.yaml")
		if f, err := filepath.Glob(pattern); err != nil {
			log.Error(errors.Wrapf(err, "glob failed, pattern %v", pattern))
		} else {
			files = append(files, f...)
		}
	}

	return files
}
