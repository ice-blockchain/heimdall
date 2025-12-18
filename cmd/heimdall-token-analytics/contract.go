// SPDX-License-Identifier: ice License 1.0

package main

import (
	"errors"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	ta "github.com/ice-blockchain/heimdall/token-analytics"
)

type (
	Config struct {
		Version    string `yaml:"version"`
		HTTPServer struct {
			CertPath string `yaml:"certPath"`
			KeyPath  string `yaml:"keyPath"`
			Port     uint32 `yaml:"port"`
		} `yaml:"httpServer"`
		Development           bool   `yaml:"development"`
		IdentityServiceURL    string `yaml:"identityServiceUrl"`
		IdentityServiceAPIKey string `yaml:"identityServiceApiKey"`
	}

	service struct {
		tokenAnalytics ta.TokenAnalytics
		httpServer     server.Server
	}
)

const (
	applicationYamlKey = "cmd/heimdall-token-analytics"

	invalidPropertiesErrorCode = "INVALID_PROPERTIES"
	sessionNotFoundErrorCode   = "SESSION_NOT_FOUND"
)

var (
	errNoCertificateAvailable = errors.New("no certificate available")
)
