// SPDX-License-Identifier: ice License 1.0

package main

import tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"

type (
	service struct {
		tokenAnalytics tokenanalytics.TokenAnalytics
	}
	noAuth struct{}
)

const (
	applicationYamlKey = "cmd/heimdall-token-analytics"
)
