// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	_ "embed"

	"github.com/alitto/pond/v2"
	"github.com/pkg/errors"

	szhttp "github.com/ice-blockchain/subzero/server/http"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type (
	Relays interface {
		GetAllIONConnectRelays(ctx context.Context, requestedRelay string) ([]string, error)
		IONConnectRelaysForUser(ctx context.Context, userId string, followeeMasterKeys []string) ([]string, error)
	}
	RelaysSyncer interface {
		CheckRelayStatus(ctx context.Context) error
	}
)

var (
	ErrNoRelays = errors.Errorf("no relays")
)

var (
	//go:embed DDL.sql
	ddl string
)

const (
	applicationYamlKey = "relay-management"
)

type (
	config struct {
		Workers int `yaml:"workers"`
	}
	relaysRepository struct {
		db       *storage.DB
		shutdown func() error
		cfg      *config
	}
	relaysSyncer struct {
		db         *storage.DB
		shutdown   func() error
		cfg        *config
		workerPool pond.ResultPool[nip11Result]
	}

	ionConnectRelays struct {
		IONConnectRelays []string `db:"ion_connect_relays"`
	}
	nip11Result struct {
		url   string
		nip11 *szhttp.RelayInformationDocument
		err   error
	}
)
