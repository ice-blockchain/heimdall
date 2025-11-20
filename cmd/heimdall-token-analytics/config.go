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

func loadTLSConfigFromPEM(certPEM, keyPEM, pullCAPEM string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	return buildTLSConfig(cert, pullCAPEM, nil)
}

func loadTLSConfigFromFiles(certFile, keyFile, pullCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	var pullCAData string
	if pullCAFile != "" {
		pull, err := os.ReadFile(pullCAFile)
		if err != nil {
			return nil, err
		}
		pullCAData = string(pull)
	}

	return buildTLSConfig(cert, pullCAData, nil)
}

func buildTLSConfig(cert tls.Certificate, caPEM string, pool *x509.CertPool) (*tls.Config, error) {
	var err error

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	if caPEM != "" && pool == nil {
		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(caPEM))
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  pool,
	}
	config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if err := info.SupportsCertificate(&cert); err == nil {
			return &cert, nil
		}

		slog.Error("no certificate available for server name", "serverName", info.ServerName, "remote", info.Conn.RemoteAddr().String())
		return nil, errNoCertificateAvailable
	}

	return config, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
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
	} else if pathExists(c.HTTPServer.CertPath) && pathExists(c.HTTPServer.KeyPath) {
		slog.Info("loading TLS config from certificate files")
		tlsConf, err = loadTLSConfigFromFiles(c.HTTPServer.CertPath, c.HTTPServer.KeyPath, "")
	} else if c.HTTPServer.CertPath != "" && c.HTTPServer.KeyPath != "" {
		slog.Info("loading TLS config from PEM data")
		tlsConf, err = loadTLSConfigFromPEM(c.HTTPServer.CertPath, c.HTTPServer.KeyPath, "")
	} else {
		err = errNoCertificateAvailable
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
