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
		DeliverCode(ctx context.Context, code, language, phoneNumber string) error
	}
)

type (
	smsSender struct {
		smsClient sms.Client
	}
	languageCode = string
	smsTemplate  struct {
		body *template.Template
		Body string
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
		"2fa_recovery",
	}
)
