// SPDX-License-Identifier: ice License 1.0

package main

import (
	_ "embed"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

type (
	service struct {
		coinSyncer coins.Sync
		accounts   accounts.Accounts
		db         *storage.DB
		privateKey string
		publicKey  string
	}
	noAuth struct{}
	config struct {
		PrivateKey string `yaml:"privateKey" mapstructure:"privateKey"`
		Version    string `yaml:"version"`
	}
	verifiedUserQueueData struct {
		Username         string   `db:"username"`
		MasterPubKey     string   `db:"master_pubkey"`
		IONConnectRelays []string `db:"ion_connect_relays"`
	}
)

const (
	applicationYamlKey = "cmd/heimdall-asset-data-syncer"
)

var (
	cfg config

	//go:embed DDL.sql
	ddl string
)
