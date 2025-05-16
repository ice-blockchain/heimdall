// SPDX-License-Identifier: ice License 1.0

package main

import (
	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
)

type (
	service struct {
		coinSyncer              coins.Sync
		verifiedQueueRepository accounts.VerifiedUsersSync
		relayLivenessCheck      relaymanagement.RelaysSyncer
	}
	noAuth struct{}
)

const (
	applicationYamlKey = "cmd/heimdall-asset-data-syncer"
)
