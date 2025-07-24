// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-identity-io/api"
	"github.com/ice-blockchain/heimdall/coins"
	hashtagstatistics "github.com/ice-blockchain/heimdall/hashtag-statistics"
	nftcontent "github.com/ice-blockchain/heimdall/nft-content"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/database/query"
	"github.com/ice-blockchain/subzero/validation"
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

	query.MustInit(ctx, query.WithConfig(&query.Config{
		PrivateKey: cfg.Query.PrivateKey,
		RelayURL:   cfg.Query.RelayURL,
		WriteURLs:  cfg.Query.WriteURLs,
		ReadURLs:   cfg.Query.ReadURLs,
	}))
	validation.MustInit(validation.WithSkipProfileMetadataProofEventsVerify())

	api.SwaggerInfo.Host = cfg.Host
	api.SwaggerInfo.Version = cfg.Version
	auth := accounts.NewDelegatedRPAuth(ctx)
	server.New(&service{cfg: &cfg}, applicationYamlKey, "/docs").ListenAndServe(ctx, cancel, auth)
}

func init() {
	mountContentCategoriesConfig()
	mountTranslationsConfig()
}

func mountContentCategoriesConfig() {
	for _, contentType := range mustReadDir(contentTopics, "content-topics") {
		allLanguagesJsonPath := fmt.Sprintf("content-topics/%v", contentType.Name())
		for language, content := range mustReadJSONFile[map[string]map[string]any](contentTopics, allLanguagesJsonPath) {
			cfgKey := fmt.Sprintf("content-topics_%v_%v", strings.ReplaceAll(contentType.Name(), ".json", ""), language)
			version, err := strconv.Atoi(fmt.Sprint(content["_version"]))
			log.Panic(err)
			allValidConfigNames[cfgKey] = func(_ *config) (any, Version) {
				return content, Version(version)
			}
		}
	}
}

func mountTranslationsConfig() {
	for _, appName := range mustReadDir(translations, "translations") {
		usecasePath := fmt.Sprintf("translations/%v", appName.Name())
		for _, usecase := range mustReadDir(translations, usecasePath) {
			jsonPath := fmt.Sprintf("translations/%v/%v", appName.Name(), usecase.Name())
			for language, content := range mustReadJSONFile[map[string]map[string]any](translations, jsonPath) {
				cfgKey := fmt.Sprintf("%v_%v_translations_%v", appName.Name(), strings.ReplaceAll(usecase.Name(), ".json", ""), language)
				version, err := strconv.Atoi(fmt.Sprint(content["_version"]))
				log.Panic(err)
				allValidConfigNames[cfgKey] = func(_ *config) (any, Version) {
					return content, Version(version)
				}
			}
		}
	}
}

func mustReadDir(fs embed.FS, path string) []fs.DirEntry {
	entries, err := fs.ReadDir(path)
	log.Panic(err)

	return entries
}

func mustReadJSONFile[T any](fs embed.FS, path string) T {
	fileContents, err := fs.ReadFile(path)
	log.Panic(err)

	var t T
	log.Panic(json.Unmarshal(fileContents, &t))

	return t
}

func (s *service) RegisterRoutes(router *server.Router) {
	s.setupDelegatedRPProxyRoutes(router)
	s.setup2FARoutes(router)
	s.setupUserRoutes(router)
	s.setupWalletViewsRoutes(router)
	s.setupCoinRoutes(router)
	s.setupStatisticsRoutes(router)
	s.setupSocialProfileRoutes(router)
}

func (s *service) Init(ctx context.Context, cancel context.CancelFunc) {
	s.coins = coins.New(ctx)
	s.relays = relaymanagement.NewRelays(ctx)
	var appsRuntimeCfg accounts.AppsRuntimeConfig
	appcfg.MustLoadFromKey(runtimeConfigApplicationYamlKey, &appsRuntimeCfg)
	allValidConfigNames["apps-runtime_ion-app"] = func(cfg *config) (any, Version) {
		return appsRuntimeCfg.IONApp, Version(appsRuntimeCfg.IONApp.Version)
	}
	s.accounts = accounts.New(ctx, s.coins, s.relays, &appsRuntimeCfg)
	s.hashtagStatistics = hashtagstatistics.New(ctx)
	s.nftContent = nftcontent.New(ctx)

	publicKey := s.accounts.PublicKey()
	allValidConfigNames[configNameServicePubkeys] = func(_ *config) (any, Version) { return []string{publicKey}, Version(1) }
}

func (s *service) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Wrap(ctx.Err(), "could not close repository because context ended")
	}

	return multierror.Append(
		errors.Wrap(s.accounts.Close(), "failed to close accounts"),
		errors.Wrap(s.coins.Close(), "failed to close coins"),
		errors.Wrap(s.hashtagStatistics.Close(), "failed to close hashtag statistics"),
		errors.Wrap(s.nftContent.Close(), "failed to close nft content"),
	).ErrorOrNil()
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...", "package", "accounts")

	return multierror.Append(
		errors.Wrapf(s.accounts.HealthCheck(ctx), "accounts check failed"),
		errors.Wrapf(s.coins.HealthCheck(ctx), "coins check failed"),
		errors.Wrapf(s.hashtagStatistics.HealthCheck(ctx), "hashtag statistics check failed"),
		errors.Wrapf(s.nftContent.HealthCheck(ctx), "nft content check failed"),
	).ErrorOrNil()
}
