// SPDX-License-Identifier: ice License 1.0

package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"strings"
	"sync/atomic"

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
		cfg:            &cfg,
		emailClients:   make([]email.Client, 0, cfg.ExtraLoadBalancersCount+1),
		fromRecipients: make([]fromRecipient, 0, cfg.ExtraLoadBalancersCount+1),
	}
	em.emailClients = append(em.emailClients, email.New(applicationYamlKey))
	em.fromRecipients = append(em.fromRecipients, fromRecipient{cfg.FromEmailName, cfg.FromEmailAddress})
	for i := range cfg.ExtraLoadBalancersCount {
		var nestedCfg config
		appcfg.MustLoadFromKey(fmt.Sprintf("%v/%v", applicationYamlKey, i+1), &nestedCfg)
		em.emailClients = append(em.emailClients, email.New(fmt.Sprintf("%v/%v", applicationYamlKey, i+1)))
		em.fromRecipients = append(em.fromRecipients, fromRecipient{nestedCfg.FromEmailName, nestedCfg.FromEmailAddress})
	}
	return &em
}

func loadEmailTranslationTemplates() { //nolint:funlen,gocognit,revive // .
	const totalLanguages = 50
	allEmailTemplates = make(map[string]map[languageCode]*emailTemplate, len(allEmailTypes))
	for _, emailType := range allEmailTypes {
		files, err := translations.ReadDir(fmt.Sprintf("translations/%v", emailType))
		if err != nil {
			panic(err)
		}
		allEmailTemplates[emailType] = make(map[languageCode]*emailTemplate, totalLanguages)
		for _, file := range files {
			content, fErr := translations.ReadFile(fmt.Sprintf("translations/%v/%v", emailType, file.Name()))
			if fErr != nil {
				panic(fErr)
			}
			fileName := strings.Split(file.Name(), ".")
			language := fileName[0]
			ext := fileName[1]
			var tmpl emailTemplate
			switch ext {
			case "txt":
				err = json.Unmarshal(content, &tmpl)
				if err != nil {
					panic(err)
				}
				subject := template.Must(template.New(fmt.Sprintf("email_%v_%v_subject", emailType, language)).Parse(tmpl.Subject))
				if allEmailTemplates[emailType][language] != nil {
					allEmailTemplates[emailType][language].subject = subject
					allEmailTemplates[emailType][language].Subject = tmpl.Subject
				} else {
					tmpl.subject = subject
					allEmailTemplates[emailType][language] = &tmpl
				}
			case "html":
				body := template.Must(template.New(fmt.Sprintf("email_%v_%v_body", emailType, language)).Parse(string(content)))
				if allEmailTemplates[emailType][language] != nil {
					allEmailTemplates[emailType][language].body = body
					allEmailTemplates[emailType][language].Body = string(content)
				} else {
					tmpl.body = body
					tmpl.Body = string(content)
					allEmailTemplates[emailType][language] = &tmpl
				}
			default:
				log.Panic("wrong translation file extension")
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

func (a *emailSender) DeliverCode(ctx context.Context, code, emailAddress, language string) error {
	emailType := "2fa"
	var tmpl *emailTemplate
	tmpl, ok := allEmailTemplates[emailType][language]
	if !ok {
		tmpl = allEmailTemplates[emailType][defaultLanguage]
	}
	dataBody := struct {
		Email            string
		ConfirmationCode string
	}{
		Email:            emailAddress,
		ConfirmationCode: code,
	}

	lbIdx := atomic.AddUint64(&a.emailClientLBIndex, 1) % uint64(a.cfg.ExtraLoadBalancersCount+1)

	return errors.Wrapf(a.emailClients[lbIdx].Send(ctx, &email.Parcel{
		Body: &email.Body{
			Type: email.TextHTML,
			Data: tmpl.getBody(dataBody),
		},
		Subject: tmpl.getSubject(nil),
		From: email.Participant{
			Name:  a.fromRecipients[lbIdx].FromEmailName,
			Email: a.fromRecipients[lbIdx].FromEmailAddress,
		},
	}, email.Participant{
		Name:  "",
		Email: emailAddress,
	}), "failed to send email with type:%v for user with email:%v", emailType, emailAddress)
}
