// SPDX-License-Identifier: ice License 1.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/cert"
	appcfg "github.com/ice-blockchain/wintr/config"
)

func loadTLSConfig(certFile, keyFile, pullCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	var pool *x509.CertPool

	if pullCAFile != "" {
		pull, err := os.ReadFile(pullCAFile)
		if err != nil {
			return nil, err
		}

		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(pull)
	}

	config := &tls.Config{MinVersion: tls.VersionTLS13}
	config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if err := info.SupportsCertificate(&cert); err == nil {
			return &cert, nil
		}

		slog.Error("no certificate available for server name", "serverName", info.ServerName, "remote", info.Conn.RemoteAddr().String())
		return nil, errNoCertificateAvailable
	}

	return config, nil
}

func mustLoadConfig() *Config {
	var cfg Config

	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	appcfg.MustLoadFromKey("development", &cfg.Development)

	return &cfg
}

func (c *Config) Server() *server.Config {
	var tlsConf *tls.Config
	var err error

	if (c.HTTPServer.CertPath == "" || c.HTTPServer.KeyPath == "") && c.Development {
		slog.Warn("using development self-signed certificate")
		tlsConf = cert.MustGenerateTLSConfigSelfSigned("localhost")
	} else {
		tlsConf, err = loadTLSConfig(c.HTTPServer.CertPath, c.HTTPServer.KeyPath, "")
	}

	if err != nil {
		slog.Error("failed to load TLS config", "error", err)
		panic(err)
	}

	return &server.Config{
		Port:  c.HTTPServer.Port,
		TLS:   tlsConf,
		Debug: c.Development,
	}
}
