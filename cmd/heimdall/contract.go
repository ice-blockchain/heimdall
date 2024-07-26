// SPDX-License-Identifier: ice License 1.0

package main

import (
	"time"

	"github.com/ice-blockchain/heimdall/accounts"
)

const (
	applicationYamlKey = "cmd/heimdall"
	proxyTimeout       = 30 * time.Second
)

type (
	service struct {
		accounts accounts.Accounts
		cfg      *config
	}
	config struct {
		// TODO: swagger
		//Host               string `yaml:"host"`
		//Version            string `yaml:"version"`
		ProxyDfnsEndpoints []struct {
			Endpoint string `yaml:"endpoint"`
			Method   string `yaml:"method"`
		} `yaml:"proxyDfnsEndpoints"`
	}
)
