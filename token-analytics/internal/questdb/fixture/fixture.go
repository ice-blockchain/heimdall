// SPDX-License-Identifier: ice License 1.0

package fixture

import (
	"context"
	"net"
	"net/url"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type (
	Container struct {
		testcontainers.Container
		AddressHTTP string
		AddressPG   string
	}
)

const (
	qdbImage        = "questdb/questdb:9.2.0"
	qdbLineUser     = "root"
	qdbLinePassword = "root"
	qdbPgUser       = "pgroot"
	qdbPgPassword   = "pgroot"
)

func New(ctx context.Context) (*Container, error) {
	env := map[string]string{
		"QDB_CAIRO_MAX_UNCOMMITTED_ROWS":        "1",
		"QDB_LINE_TCP_MAINTENANCE_JOB_INTERVAL": "100",
		"QDB_PG_ENABLED":                        "true",
		"QDB_HTTP_MIN_ENABLED":                  "false",
		"QDB_LINE_HTTP_ENABLED":                 "true",
		"QDB_INFLUXDB_ENABLED":                  "true",
		"QDB_HTTP_ENABLED":                      "true",
		"QDB_LINE_HTTP_USER":                    qdbLineUser,
		"QDB_LINE_HTTP_PASSWORD":                qdbLinePassword,
		"QDB_PG_PASSWORD":                       qdbPgPassword,
		"QDB_PG_USER":                           qdbPgUser,
	}

	req := testcontainers.ContainerRequest{
		Image:        qdbImage,
		ExposedPorts: []string{"9000/tcp", "8812/tcp"},
		WaitingFor:   wait.ForHTTP("/settings").WithPort("9000"),
		Env:          env,
	}

	qdbC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	ip, err := qdbC.Host(ctx)
	if err != nil {
		return nil, err
	}

	mappedPort, err := qdbC.MappedPort(ctx, "9000")
	if err != nil {
		return nil, err
	}
	httpAddress := net.JoinHostPort(ip, mappedPort.Port())

	mappedPort, err = qdbC.MappedPort(ctx, "8812")
	if err != nil {
		return nil, err
	}

	pgURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(qdbPgUser, qdbPgPassword),
		Host:   net.JoinHostPort(ip, mappedPort.Port()),
		Path:   "qdb",
	}

	return &Container{
		Container:   qdbC,
		AddressHTTP: "http::addr=" + httpAddress + ";username=" + qdbLineUser + ";password=" + qdbLinePassword,
		AddressPG:   pgURL.String(),
	}, nil
}
