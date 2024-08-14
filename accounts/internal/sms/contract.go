// SPDX-License-Identifier: ice License 1.0

package sms

import (
	"context"
	"embed"
	"text/template"

	"github.com/ice-blockchain/wintr/sms"
)

type (
	SmsSender interface {
		DeliverCode(ctx context.Context, code, phoneNumber, language string) error
	}
)

type (
	smsSender struct {
		smsClients       []sms.Client
		smsClientLBIndex uint64
		cfg              *config
	}
	languageCode = string
	smsTemplate  struct {
		body *template.Template
		Body string
	}
	config struct {
		ExtraLoadBalancersCount int `yaml:"extraLoadBalancersCount"`
	}
)

const (
	defaultLanguage = "en"
)

var (
	//go:embed translations
	translations embed.FS
	//nolint:gochecknoglobals // Its loaded once at startup.
	allTemplates map[string]map[languageCode]*smsTemplate
	allSmsTypes  []string = []string{
		"2fa",
	}
)
