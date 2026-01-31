// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-identity-io/api"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/heimdall/following"
	hashtagstatistics "github.com/ice-blockchain/heimdall/hashtag-statistics"
	indexer "github.com/ice-blockchain/heimdall/ion-indexer"
	nftcontent "github.com/ice-blockchain/heimdall/nft-content"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/heimdall/server"
	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
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
			allValidConfigNames[cfgKey] = func(_ *config, _ *Version) (any, *Version) {
				v := Version(version)
				return content, &v
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
				allValidConfigNames[cfgKey] = func(_ *config, _ *Version) (any, *Version) {
					v := Version(version)
					return content, &v
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
	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization", "X-Client-ID", "X-Language", "X-Version"},
		AllowCredentials: false,
	}
	router.Use(cors.New(corsConfig))

	s.setupDelegatedRPProxyRoutes(router)
	s.setup2FARoutes(router)
	s.setupUserRoutes(router)
	s.setupWalletViewsRoutes(router)
	s.setupCoinRoutes(router)
	s.setupStatisticsRoutes(router)
	s.setupSocialProfileRoutes(router)
	s.setupNFTRoutes(router)
	s.setupDeviceIdentificationRoutes(router)
	s.setupCommunityTokenRoutes(router)
}

func (s *service) Init(ctx context.Context, cancel context.CancelFunc) {
	s.relays = relaymanagement.NewRelays(ctx)
	s.ionConnectClient = relaymanagement.NewIonConnectClient()
	var appsRuntimeCfg accounts.AppsRuntimeConfig
	appcfg.MustLoadFromKey(runtimeConfigApplicationYamlKey, &appsRuntimeCfg)
	allValidConfigNames["apps-runtime_ion-app"] = func(_ *config, _ *Version) (any, *Version) {
		v := Version(appsRuntimeCfg.IONApp.Version)
		return appsRuntimeCfg.IONApp, &v
	}
	allValidConfigNames["multiswap"] = func(cfg *config, ver *Version) (any, *Version) {
		if ver == nil {
			return errors.Wrapf(errVersionRequired, "version required for multiswap"), nil
		}
		return cfg.MultiSwap, &cfg.MultiSwap.Version
	}
	ta := tokenanalytics.NewUserRepository(ctx)
	s.tokenAnalytics = ta
	s.coins = coins.New(ctx, ta)
	testnet := false
	for _, n := range s.coins.GetAllNetworks() {
		if n.IsTestnet {
			testnet = true
			break
		}
	}
	ionIndexer := indexer.New(testnet)
	s.accounts = accounts.New(ctx, s.coins, s.relays, &appsRuntimeCfg, s.tokenAnalytics, ionIndexer)
	if err := s.accounts.InitializeIdentityKeypairs(ctx); err != nil {
		log.Panic(errors.Wrap(err, "failed to initialize identity keypairs - service cannot start without them"))
	}
	s.validation = validation.New(ctx, validation.WithIONIdentityPublicKeys(func() []string {
		return []string{s.accounts.PublicKey()}
	}))
	s.hashtagStatistics = hashtagstatistics.New(ctx)
	s.nftContent = nftcontent.New(ctx, s.accounts, ionIndexer, s.tokenAnalytics)
	s.following = following.New(ctx)
	s.deviceIdentificationProxy = accounts.NewDeviceIdentificationProxy(ctx, s.cfg.Version)
	publicKey := s.accounts.PublicKey()
	allValidConfigNames[configNameServicePubkeys] = func(_ *config, _ *Version) (any, *Version) {
		v1 := Version(1)
		return []string{publicKey}, &v1
	}
	allValidConfigNames["global_accounts"] = func(_ *config, ver *Version) (any, *Version) {
		reqCtx, reqCancel := context.WithTimeout(ctx, 25*time.Second)
		defer reqCancel()
		var currentVer uint64
		if ver != nil {
			currentVer = uint64(*ver)
		} else {
			return errors.Wrapf(errVersionRequired, "version required for global_accounts"), nil
		}
		accs, newVer, err := s.accounts.GetGlobalAccounts(reqCtx, currentVer)
		v := Version(0)
		if err != nil {
			return err, &v
		}
		v = Version(newVer)
		return accs, &v
	}
	allValidConfigNames["nsfw_accounts"] = func(_ *config, ver *Version) (any, *Version) {
		reqCtx, reqCancel := context.WithTimeout(ctx, 25*time.Second)
		defer reqCancel()
		var currentVer uint64
		if ver != nil {
			currentVer = uint64(*ver)
		} else {
			return errors.Wrapf(errVersionRequired, "version required for nsfw_accounts"), nil
		}
		accs, newVer, err := s.accounts.GetNSFWAccounts(reqCtx, currentVer)
		if err != nil {
			return err, nil
		}
		v := Version(newVer)
		return accs, &v
	}
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
		errors.Wrap(s.tokenAnalytics.Close(), "failed to close token analytics"),
	).ErrorOrNil()
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...", "package", "accounts")

	return multierror.Append(
		errors.Wrapf(s.accounts.HealthCheck(ctx), "accounts check failed"),
		errors.Wrapf(s.coins.HealthCheck(ctx), "coins check failed"),
		errors.Wrapf(s.hashtagStatistics.HealthCheck(ctx), "hashtag statistics check failed"),
		errors.Wrapf(s.nftContent.HealthCheck(ctx), "nft content check failed"),
		// TODO: re-enable when token analytics is stable.
		// errors.Wrapf(s.tokenAnalytics.HealthCheck(ctx), "token analytics check failed"),
	).ErrorOrNil()
}
