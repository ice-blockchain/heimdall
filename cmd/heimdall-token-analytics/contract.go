// SPDX-License-Identifier: ice License 1.0

package main

import (
	"errors"

	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
	"github.com/ice-blockchain/heimdall/token-analytics/server"
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
	}

	service struct {
		tokenAnalytics tokenanalytics.TokenAnalytics
		httpServer     server.Server
	}
)

const (
	applicationYamlKey = "cmd/heimdall-token-analytics"
)

var (
	errNoCertificateAvailable = errors.New("no certificate available")
)
