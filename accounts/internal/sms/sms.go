// SPDX-License-Identifier: ice License 1.0

package sms

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"text/template"

	"github.com/pkg/errors"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/sms"
)

func init() {
	loadTranslations()
}

func New(applicationYamlKey string) SmsSender {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	smsClient := &smsSender{
		cfg:        &cfg,
		smsClients: make([]sms.Client, 0, cfg.ExtraLoadBalancersCount+1),
	}
	smsClient.smsClients = append(smsClient.smsClients, sms.New(applicationYamlKey))
	for i := range cfg.ExtraLoadBalancersCount {
		var nestedCfg config
		appcfg.MustLoadFromKey(fmt.Sprintf("%v/%v", applicationYamlKey, i+1), &nestedCfg)
		smsClient.smsClients = append(smsClient.smsClients, sms.New(fmt.Sprintf("%v/%v", applicationYamlKey, i+1)))
	}
	return smsClient
}

func (a *smsSender) DeliverCode(ctx context.Context, code, phoneNumber, language string) error {
	smsType := "2fa"
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

	lbIdx := atomic.AddUint64(&a.smsClientLBIndex, 1) % uint64(a.cfg.ExtraLoadBalancersCount+1)

	return errors.Wrapf(a.smsClients[lbIdx].Send(ctx, &sms.Parcel{
		SendAt:   nil,
		ToNumber: phoneNumber,
		Message:  tmpl.getBody(dataBody),
	}), "failed to send sms with type:%v for user with phoneNumber:%v", smsType, phoneNumber)
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
		files, err := translations.ReadDir(fmt.Sprintf("translations/%v", smsType))
		if err != nil {
			panic(err)
		}
		allTemplates[smsType] = make(map[languageCode]*smsTemplate, totalLanguages)
		for _, file := range files {
			content, fErr := translations.ReadFile(fmt.Sprintf("translations/%v/%v", smsType, file.Name()))
			if fErr != nil {
				panic(fErr)
			}
			fileName := strings.Split(file.Name(), ".")
			language := languageCode(fileName[0])
			ext := fileName[1]
			var tmpl smsTemplate
			switch ext {
			case "txt":
				body := template.Must(template.New(fmt.Sprintf("sms_%v_%v_subject", smsType, language)).Parse(string(content)))
				if allTemplates[smsType][language] != nil {
					allTemplates[smsType][language].body = body
					allTemplates[smsType][language].Body = tmpl.Body
				} else {
					tmpl.body = body
					allTemplates[smsType][language] = &tmpl
				}
			default:
				log.Panic("wrong translation file extension")
			}
		}
	}
}
