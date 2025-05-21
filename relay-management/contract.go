// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	_ "embed"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/server/http/nip11"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type (
	Relays interface {
		GetAllIONConnectRelays(ctx context.Context, requestedRelay string) ([]string, error)
		IONConnectRelaysForUser(ctx context.Context, userId string) ([]string, error)
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
	relaysRepository struct {
		db       *storage.DB
		shutdown func() error
	}
	relaysSyncer struct {
		db       *storage.DB
		shutdown func() error
	}

	ionConnectRelays struct {
		IONConnectRelays []string `db:"ion_connect_relays"`
	}
	nip11Result struct {
		url   string
		nip11 *nip11.RelayInformationDocument
		err   error
	}
)
