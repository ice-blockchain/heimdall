// SPDX-License-Identifier: ice License 1.0

package sms

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/sms"
)

func init() {
	loadTranslations()
}

func New(applicationYamlKey string) SmsSender {
	smsClient := &smsSender{
		smsClient: sms.New(applicationYamlKey),
	}

	return smsClient
}

func (a *smsSender) DeliverCode(ctx context.Context, code, language string, phoneNumbers []string) error {
	smsType := "2fa_recovery"
	var tmpl *smsTemplate
	tmpl, ok := allTemplates[smsType][language]
	if !ok {
		tmpl = allTemplates[smsType][defaultLanguage]
	}
	dataBody := struct {
		ConfirmationCode string
	}{
		ConfirmationCode: code,
	}

	return errors.Wrapf(a.smsClient.Send(ctx, &sms.Parcel{
		SendAt:   nil,
		ToNumber: phoneNumbers[0],
		Message:  tmpl.getBody(dataBody),
	}), "failed to send sms with type:%v for user with phoneNumber:%v", smsType, phoneNumbers[0])
}

func (t *smsTemplate) getBody(data any) string {
	if data == nil {
		return t.Body
	}
	bf := new(bytes.Buffer)
	log.Panic(errors.Wrapf(t.body.Execute(bf, data), "failed to execute body template for data:%#v", data))

	return bf.String()
}

func loadTranslations() { //nolint:funlen,gocognit,revive // .
	const totalLanguages = 50
	allTemplates = make(map[string]map[languageCode]*smsTemplate, len(allSmsTypes))
	for _, smsType := range allSmsTypes {
		allTemplates[smsType] = make(map[languageCode]*smsTemplate, totalLanguages)
		content, fErr := translations.ReadFile(fmt.Sprintf("translations/%v.json", smsType))
		if fErr != nil {
			panic(fErr)
		}
		var tmpl smsTemplate
		var languageData map[string]*struct {
			Text string `json:"text"`
		}
		log.Panic(errors.Wrapf(json.Unmarshal(content, &languageData), "failed to load json sms translations file%v", smsType))
		for language, data := range languageData {
			body := template.Must(template.New(fmt.Sprintf("sms_%v_%v_subject", smsType, language)).Parse(data.Text))
			if allTemplates[smsType][language] != nil {
				allTemplates[smsType][language].body = body
				allTemplates[smsType][language].Body = tmpl.Body
			} else {
				tmpl.body = body
				allTemplates[smsType][language] = &tmpl
			}
		}
	}
}
