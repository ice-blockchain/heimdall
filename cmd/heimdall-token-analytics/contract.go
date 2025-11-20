// SPDX-License-Identifier: ice License 1.0

package main

import (
	"errors"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	ta "github.com/ice-blockchain/heimdall/token-analytics"
)

type (
	Config struct {
		Version     string `yaml:"version"`
		Development bool   `yaml:"development"`
		HTTPServer  struct {
			CertPath string `yaml:"certPath"`
			KeyPath  string `yaml:"keyPath"`
			Port     uint32 `yaml:"port"`
		} `yaml:"httpServer"`
		TokenizedCommunities struct {
			BondingCurveSmartContractAddress string `yaml:"bondingCurveSmartContractAddress" mapstructure:"bondingCurveSmartContractAddress"`
		} `yaml:"tokenizedCommunities" mapstructure:"tokenizedCommunities"`
	}

	service struct {
		tokenAnalytics ta.TokenAnalytics
		httpServer     server.Server
	}
)

const (
	applicationYamlKey = "cmd/heimdall-token-analytics"

	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
)

var (
	errNoCertificateAvailable = errors.New("no certificate available")
)
