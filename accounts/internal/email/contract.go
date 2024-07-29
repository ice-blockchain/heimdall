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
		DeliverCode(ctx context.Context, code, emailAddress, language string) error
	}
)

type (
	emailSender struct {
		emailClients       []email.Client
		fromRecipients     []fromRecipient
		emailClientLBIndex uint64
		cfg                *config
	}
	fromRecipient struct {
		FromEmailName    string
		FromEmailAddress string
	}
	config struct {
		ExtraEmailLoadBalancersCount int    `yaml:"extraEmailLoadBalancersCount"`
		FromEmailName                string `yaml:"fromEmailName"`
		FromEmailAddress             string `yaml:"fromEmailAddress"`
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
		"2fa",
	}
)
