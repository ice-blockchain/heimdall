// SPDX-License-Identifier: ice License 1.0

package main

import (
	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
)

type (
	service struct {
		coinSyncer coins.Sync
		accounts   accounts.Accounts
		coins      coins.Coins
	}
	noAuth struct{}
)

const (
	applicationYamlKey = "cmd/heimdall-asset-data-syncer"
)
