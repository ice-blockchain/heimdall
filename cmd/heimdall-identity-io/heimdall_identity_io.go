// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-identity-io/api"
	"github.com/ice-blockchain/heimdall/coins"
	hashtagstatistics "github.com/ice-blockchain/heimdall/hashtag-statistics"
	"github.com/ice-blockchain/heimdall/server"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

// @title						User accounts management for ION
// @version					latest
// @description				It is responsible for providing off chain account management for the ION Platform; it is the first layer of interaction between users and the platform.
// @query.collection.format	multi
// @schemes					https
// @contact.name				ice.io
// @contact.url				https://ice.io
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	api.SwaggerInfo.Host = cfg.Host
	api.SwaggerInfo.Version = cfg.Version
	auth := accounts.NewDelegatedRPAuth(ctx)
	server.New(&service{cfg: &cfg}, applicationYamlKey, "/docs").ListenAndServe(ctx, cancel, auth)
}

func init() {
	files, err := contentCategories.ReadDir("content-categories")
	log.Panic(err)

	contentCategoriesFiles := make(map[string][]map[string]string)
	for _, entry := range files {
		file, rErr := contentCategories.ReadFile(fmt.Sprintf("content-categories/%v", entry.Name()))
		log.Panic(rErr)
		var fileContent []map[string]string
		log.Panic(json.Unmarshal(file, &fileContent))
		contentCategoriesFiles[entry.Name()] = fileContent
	}

	type contentCategoryKey struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	contentCategoriesPerLanguage := make(map[string][]contentCategoryKey)
	for contentCategoryType, content := range contentCategoriesFiles {
		for _, languageVariant := range content {
			var key string
			for field, value := range languageVariant {
				if field == "key" {
					key = value
					break
				}
			}
			for field, value := range languageVariant {
				if field != "key" {
					cfgName := fmt.Sprintf("%v_%v", strings.Replace(contentCategoryType, ".json", "", 1), field)
					contentCategoriesPerLanguage[cfgName] = append(contentCategoriesPerLanguage[cfgName], contentCategoryKey{Key: key, Name: value})
				}
			}
		}
	}
	for k, v := range contentCategoriesPerLanguage {
		allValidConfigNames[k] = func(_ *config) (any, Version) {
			return v, Version(0)
		}
	}

	log.Panic(json.Unmarshal([]byte(ionAppTranslations), &ionAppTranslationsRawJSON))
}

func (s *service) RegisterRoutes(router *server.Router) {
	s.setupDelegatedRPProxyRoutes(router)
	s.setup2FARoutes(router)
	s.setupUserRoutes(router)
	s.setupWalletViewsRoutes(router)
	s.setupCoinRoutes(router)
	s.setupStatisticsRoutes(router)
}

func (s *service) Init(ctx context.Context, cancel context.CancelFunc) {
	s.coins = coins.New(ctx)
	s.accounts = accounts.New(ctx, s.coins)
	s.hashtagStatistics = hashtagstatistics.New(ctx)
}

func (s *service) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Wrap(ctx.Err(), "could not close repository because context ended")
	}

	return multierror.Append(
		errors.Wrap(s.accounts.Close(), "failed to close accounts"),
		errors.Wrap(s.coins.Close(), "failed to close coins"),
		errors.Wrap(s.hashtagStatistics.Close(), "failed to close hashtag statistics"),
	).ErrorOrNil()
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...", "package", "accounts")

	return multierror.Append(
		errors.Wrapf(s.accounts.HealthCheck(ctx), "accounts check failed"),
		errors.Wrapf(s.coins.HealthCheck(ctx), "coins check failed"),
		errors.Wrapf(s.hashtagStatistics.HealthCheck(ctx), "hashtag statistics check failed"),
	).ErrorOrNil()
}
