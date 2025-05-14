// SPDX-License-Identifier: ice License 1.0

package main

import (
	_ "embed"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
)

type (
	service struct {
		coinSyncer              coins.Sync
		verifiedQueueRepository accounts.Accounts
	}
	noAuth struct{}
	config struct {
		Version string `yaml:"version"`
	}
)

const (
	applicationYamlKey = "cmd/heimdall-asset-data-syncer"
)
