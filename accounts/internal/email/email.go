// SPDX-License-Identifier: ice License 1.0

package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/email"
	"github.com/ice-blockchain/wintr/log"
)

//nolint:gochecknoinits // We load embedded stuff at runtime.
func init() {
	loadEmailTranslationTemplates()
}

func New(applicationYamlKey string) EmailSender {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	em := emailSender{
		cfg:           &cfg,
		emailClient:   email.New(applicationYamlKey),
		fromRecipient: fromRecipient{cfg.FromEmailName, cfg.FromEmailAddress},
	}
	return &em
}

func loadEmailTranslationTemplates() { //nolint:funlen,gocognit,revive // .
	const totalLanguages = 50
	allEmailTemplates = make(map[string]map[languageCode]*emailTemplate, len(allEmailTypes))
	for _, emailType := range allEmailTypes {
		allEmailTemplates[emailType] = make(map[languageCode]*emailTemplate, totalLanguages)
		content, fErr := translations.ReadFile(fmt.Sprintf("translations/%v.json", emailType))
		if fErr != nil {
			panic(fErr)
		}
		var languageData map[string]emailTemplate
		log.Panic(errors.Wrapf(json.Unmarshal(content, &languageData), "failed to load json email/translations for %v", emailType))
		for language, tmpl := range languageData {
			subject := template.Must(template.New(fmt.Sprintf("email_%v_%v_subject", emailType, language)).Parse(tmpl.Subject))
			if allEmailTemplates[emailType][language] != nil {
				allEmailTemplates[emailType][language].subject = subject
				allEmailTemplates[emailType][language].Subject = tmpl.Subject
			} else {
				tmpl.subject = subject
				allEmailTemplates[emailType][language] = &tmpl
			}
			body := template.Must(template.New(fmt.Sprintf("email_%v_%v_body", emailType, language)).Parse(tmpl.Body))
			if allEmailTemplates[emailType][language] != nil {
				allEmailTemplates[emailType][language].body = body
				allEmailTemplates[emailType][language].Body = string(content)
			} else {
				tmpl.body = body
				tmpl.Body = string(content)
				allEmailTemplates[emailType][language] = &tmpl
			}
		}
	}
}

func (t *emailTemplate) getSubject(data any) string {
	if data == nil {
		return t.Subject
	}
	bf := new(bytes.Buffer)
	log.Panic(errors.Wrapf(t.subject.Execute(bf, data), "failed to execute subject template for data:%#v", data))

	return bf.String()
}

func (t *emailTemplate) getBody(data any) string {
	if data == nil {
		return t.Body
	}
	bf := new(bytes.Buffer)
	log.Panic(errors.Wrapf(t.body.Execute(bf, data), "failed to execute body template for data:%#v", data))

	return bf.String()
}

func (a *emailSender) DeliverCode(ctx context.Context, code, language string, deliverTo []string) error {
	emailType := "2fa_recovery"
	var tmpl *emailTemplate
	tmpl, ok := allEmailTemplates[emailType][language]
	if !ok {
		tmpl = allEmailTemplates[emailType][defaultLanguage]
	}
	dataBody := struct {
		Email            string
		ConfirmationCode string
	}{
		Email:            "{{.Email}}",
		ConfirmationCode: code,
	}

	participants := make([]email.Participant, 0, len(deliverTo))
	for _, emailAddress := range deliverTo {
		participants = append(participants, email.Participant{
			Name:               "",
			Email:              emailAddress,
			SubstitutionFields: map[string]string{"{{.Email}}": emailAddress},
		})
	}

	return errors.Wrapf(a.emailClient.Send(ctx, &email.Parcel{
		Body: &email.Body{
			Type: email.TextHTML,
			Data: tmpl.getBody(dataBody),
		},
		Subject: tmpl.getSubject(nil),
		From: email.Participant{
			Name:  a.fromRecipient.FromEmailName,
			Email: a.fromRecipient.FromEmailAddress,
		},
	}, participants...), "failed to send email with type:%v for user with emails:%v", emailType, deliverTo)
}
