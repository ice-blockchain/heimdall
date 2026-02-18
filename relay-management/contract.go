// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"
	_ "embed"
	"net/url"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/server/http/nip11/fetcher"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type (
	Relays interface {
		GetAllIONConnectRelays(ctx context.Context, requestedRelay *url.URL) ([]*UserAssignedRelay, error)
		IONConnectRelaysForUser(ctx context.Context, userId string) ([]*UserAssignedRelay, error)
	}
	UserAssignedRelay struct {
		URL  string `json:"url"`
		Type string `json:"type,omitempty"`
	}
	UserAssignedRelays []*UserAssignedRelay
	RelaysSyncer       interface {
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
		IONConnectRelays UserAssignedRelays `db:"ion_connect_relays"`
	}
	nip11Result struct {
		url   string
		nip11 *fetcher.RelayInformationDocument
		err   error
	}
)
