// SPDX-License-Identifier: ice License 1.0

package email

import (
	"context"
	"embed"
	"html/template"

	"github.com/ice-blockchain/wintr/email"
)

type (
	EmailSender interface {
		DeliverCode(ctx context.Context, code, language string, emailAddress string) error
	}
)

type (
	emailSender struct {
		emailClient      email.Client
		cfg              *config
		FromEmailName    string
		FromEmailAddress string
	}
	config struct {
		FromEmailName    string `yaml:"fromEmailName"`
		FromEmailAddress string `yaml:"fromEmailAddress"`
	}
	emailTemplate struct {
		subject, body *template.Template
		Subject       string `json:"subject"` //nolint:revive // That's intended.
		Body          string `json:"body"`    //nolint:revive // That's intended.
	}
	languageCode = string
)

const defaultLanguage = "en"

var (
	//go:embed translations
	translations embed.FS
	//nolint:gochecknoglobals // Its loaded once at startup.
	allEmailTemplates map[string]map[languageCode]*emailTemplate
	allEmailTypes     = []string{
		"2fa_recovery",
	}
)
