// SPDX-License-Identifier: ice License 1.0

package coins

import (
	"context"
	"fmt"
	stdlog "log"
	"math"
	"strings"
	stdlibtime "time"

	"github.com/pkg/errors"
	"github.com/rcrowley/go-metrics"

	"github.com/ice-blockchain/heimdall/coins/internal/coingecko"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func MustStartSyncer(ctx context.Context, cancel context.CancelFunc) Sync {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	s := &coinSync{
		cancel:          cancel,
		cfg:             &cfg,
		coinGeckoClient: coingecko.New(applicationYamlKey),
	}

	iceCoin, err := s.coinGeckoClient.GetCoins(ctx, []string{DefaultWalletViewCoinSymbolGroup})
	log.Panic(errors.Wrapf(err, "failed to sync ice price from coin gecko on startup"))
	if len(iceCoin) == 0 {
		log.Panic(errors.New("ice coin not found on coin gecko"))
	}
	db := storage.MustConnect(ctx, fmt.Sprintf(ddl, syncFrequency(s.cfg, DefaultWalletViewCoinSymbolGroup), iceCoin[0].PriceUSD), applicationYamlKey)
	s.db = db
	s.shutdown = db.Close
	registry := metrics.NewRegistry()
	log.Panic(errors.Wrapf(registry.Register("iteration", metrics.NewCustomTimer(metrics.NewHistogram(metrics.NewExpDecaySample(10_000, 0.015)), metrics.NewMeter())), "failed to register timer"))
	log.Panic(errors.Wrapf(registry.Register("coin_gecko_calls", metrics.NewMeter()), "failed to register coingecko call meter"))
	go metrics.LogScaled(registry, 10*stdlibtime.Second, 1*stdlibtime.Millisecond, s)
	s.metrics = registry

	go s.sync(ctx)

	return s
}

func (s *coinSync) Close() error {
	s.cancel()
	s.wg.Wait()
	return errors.Wrapf(s.shutdown(), "failed to close coins repository")
}

func (s *coinSync) HealthCheck(ctx context.Context) error {
	if err := s.db.Ping(ctx); err != nil {
		return errors.Wrap(err, "[health-check] failed to ping DB")
	}
	return nil
}

func (s *coinSync) sync(ctx context.Context) {
	s.wg.Add(1)
	defer s.wg.Done()
	syncCtx, cancel := context.WithTimeout(context.Background(), coinSyncIterationDuration)
	s.syncCoinBatch(syncCtx)
	cancel()
	for ctx.Err() == nil {
		iterations := s.metrics.Get("iteration").(metrics.Timer)
		prevIterationTiming := iterations.Percentile(0.99)
		if prevIterationTiming == 0 {
			prevIterationTiming = 1
		}
		// We batch get tokens by network and by 30 entries (coingecko limitation), so its 1 call for coins and N for tokens per iteration, so 1+N total.
		callsPerIteration := s.metrics.Get("coin_gecko_calls").(metrics.Meter).Rate1() / float64(iterations.Rate1())
		if math.IsInf(callsPerIteration, 1) {
			callsPerIteration = float64(s.metrics.Get("coin_gecko_calls").(metrics.Meter).Count())
			if callsPerIteration < 1 {
				callsPerIteration = 1
			}
		}
		targetIterations := targetCoinGeckoCallsPerMin / callsPerIteration
		if targetIterations < 1 {
			targetIterations = 1
		}
		sleepTime := stdlibtime.Duration(coinSyncIterationDuration / stdlibtime.Duration(targetIterations))
		start := time.Now()
		syncCtx, cancel = context.WithTimeout(context.Background(), coinSyncIterationDuration)
		s.syncCoinBatch(syncCtx)
		cancel()

		stdlibtime.Sleep(sleepTime - (time.Now().Sub(*start.Time)))
	}
}

func (s *coinSync) syncCoinBatch(ctx context.Context) {
	start := time.Now()
	coinsToSync, err := s.fetchSyncableCoins(ctx, start)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch syncable coins"))
		return
	}
	coinIDs := make([]string, 0, len(coinsToSync))
	networks := map[string]string{}
	for _, c := range coinsToSync {
		for _, cID := range c.CoinGeckoCoinIDs {
			spl := strings.Split(cID, ":")
			network, cgID := spl[0], spl[1]
			coinIDs = append(coinIDs, cgID)
			networks[cgID] = network
		}
	}
	var coinsData []*coingecko.Coin

	ids := map[string]string{}
	tokensPriceData := []*coingecko.Coin{}
	for network, tokensAddrs := range coinsToSync {
		if network == "" {
			continue
		}
		var fn func(ctx context.Context, network string, contractAddresses []string) ([]*coingecko.Coin, error)
		if tokensAddrs.SyncTokenFullData {
			fn = s.getTokens(coingecko.MaxTokenAddrsGetTokenData, s.coinGeckoClient.GetTokens)
		} else {
			fn = s.getTokens(coingecko.MaxTokenAddrsGetTokenPrices, s.coinGeckoClient.GetTokenPrices)
		}
		contractAddrs := make([]string, 0, len(tokensAddrs.ContractAddresses))
		notFetched := make(map[string]bool, len(tokensAddrs.ContractAddresses))
		for _, addr := range tokensAddrs.ContractAddresses {
			spl := strings.Split(addr, ":")
			id, contractAddr := spl[0], spl[1]
			if strings.Contains(contractAddr, "/") {
				continue
			}
			contractAddrs = append(contractAddrs, contractAddr)
			notFetched[contractAddr] = true
			ids[network+":"+contractAddr] = id
		}
		tokens, err := fn(ctx, network, contractAddrs)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to sync tokens data"))
			return
		}
		if len(tokens) < len(contractAddrs) && !tokensAddrs.SyncTokenFullData {
			for _, tok := range tokens {
				delete(notFetched, tok.ContractAddress)
			}
			for notFetchedContractAddr := range notFetched {
				coinGeckoID := ids[network+":"+notFetchedContractAddr]
				coinIDs = append(coinIDs, coinGeckoID)
				networks[coinGeckoID] = network + ":" + notFetchedContractAddr
				ids[coinGeckoID] = network + ":" + notFetchedContractAddr
			}
		}
		if tokensAddrs.SyncTokenFullData {
			coinsData = append(coinsData, tokens...)
		} else {
			tokensPriceData = append(tokensPriceData, tokens...)
		}
	}

	if len(coinIDs) > 0 {
		var coinsAndMissedTokens []*coingecko.Coin
		coinsAndMissedTokens, err = s.coinGeckoClient.GetCoins(ctx, coinIDs)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to fetch market data from coin gecko for coins %#v", coinIDs))
			return
		}
		for _, c := range coinsAndMissedTokens {
			if n, hasNetwork := networks[c.ID]; hasNetwork && strings.Contains(n, ":") {
				tokensPriceData = append(tokensPriceData, c)
			} else {
				coinsData = append(coinsData, c)
			}
		}
		s.metrics.Get("coin_gecko_calls").(metrics.Meter).Mark(1)
	}
	err = s.updateCoinsData(ctx, start, coinsData, true, networks)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to write updated data from coin market cap for full data %#v", coinsData))
		return
	}
	err = s.updateCoinsData(ctx, start, tokensPriceData, false, ids)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to write updated data from coin market cap for tokens prices %#v", tokensPriceData))
		return
	}
	if len(coinsData) > 0 || len(tokensPriceData) > 0 {
		s.metrics.Get("iteration").(metrics.Timer).Update(time.Now().Sub(*start.Time))
	}
}

func (s *coinSync) getTokens(maxBatch int, callCoinGecko func(ctx context.Context, network string, contractAddresses []string) ([]*coingecko.Coin, error)) func(ctx context.Context, network string, contractAddresses []string) ([]*coingecko.Coin, error) {
	return func(ctx context.Context, network string, contractAddresses []string) ([]*coingecko.Coin, error) {
		res := make([]*coingecko.Coin, 0)
		var batches [][]string
		if len(contractAddresses) > maxBatch {
			for len(contractAddresses) > maxBatch {
				batches = append(batches, contractAddresses[:maxBatch])
				contractAddresses = contractAddresses[maxBatch+1:]
			}
			if len(contractAddresses) > 0 {
				batches = append(batches, contractAddresses)
			}
		} else {
			batches = append(batches, contractAddresses)
		}
		for _, b := range batches {
			if len(b) == 0 {
				continue
			}
			tokensData, err := callCoinGecko(ctx, network, b)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to fetch info for tokens %#v", b)
			}
			s.metrics.Get("coin_gecko_calls").(metrics.Meter).Mark(1)
			res = append(res, tokensData...)
		}
		return res, nil
	}
}

func (s *coinSync) fetchSyncableCoins(ctx context.Context, now *time.Time) (map[string]*coinToSync, error) {
	expiredDataAt := now.Add(-s.cfg.SyncTokensDataFrequency)
	coins, err := storage.Select[coinToSync](ctx, s.db,
		fmt.Sprintf(`SELECT network, 
       		 array_agg(t.network||':'||t.coingecko_coin_id)  FILTER (WHERE t.contract_address = '') AS coin_ids,
       		 array_agg(t.coingecko_coin_id||':'||t.contract_address) FILTER (WHERE t.contract_address != '')  AS contract_addresses,
       		 array_agg((t.data_updated_at < $1)) @> ARRAY[TRUE] as sync_token_full_data 
			 FROM (
				SELECT * FROM coins_sync_queue
				INNER JOIN coins ON coins_sync_queue.coin_id = coins.id
				ORDER BY coins_sync_queue.created_at ASC
				LIMIT %v
			 ) t GROUP BY network`, coinSyncIterationBatchSize), expiredDataAt,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch coins to sync data")
	}
	res := make(map[string]*coinToSync, len(coins))
	for _, c := range coins {
		res[c.Network] = c
	}
	return res, nil
}

func (s *coinSync) updateCoinsData(ctx context.Context, now *time.Time, coins []*coingecko.Coin, updateFullDataTokens bool, mapping map[string]string) error {
	params := []any{now}
	placeholders, extraParams := s.buildBatchUpdate(now, coins, mapping)
	if len(placeholders) == 0 {
		return nil
	}
	params = append(params, extraParams...)
	sql := fmt.Sprintf(`WITH upd as (
						UPDATE coins SET
						 updated_at = $1,
						 data_updated_at = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN $1 ELSE coins.data_updated_at END,
						 version = (CASE 
										  WHEN %[2]v and
											 (coins.decimals::SMALLINT != update_data.decimals::SMALLINT OR
											 coins.coingecko_coin_id != update_data.coingecko_coin_id OR
											 coins.network != update_data.network OR
											 coins.name != update_data.name OR
											 coins.contract_address != update_data.contract_address OR
											 coins.symbol != update_data.symbol OR
											 coins.symbol_group != update_data.symbol_group OR
											 coins.icon_url != update_data.icon_url)
											 THEN coins.version + 1 ELSE coins.version END),
						 price_usd = CASE WHEN update_data.price_usd = 0 and coins.price_usd !=0 THEN coins.price_usd ELSE update_data.price_usd END,
						 decimals = CASE WHEN (coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v)) AND update_data.decimals != 0 THEN update_data.decimals ELSE coins.decimals END,
						 coingecko_coin_id = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN update_data.coingecko_coin_id ELSE coins.coingecko_coin_id END,
						 name = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN update_data.name ELSE coins.name END,
						 contract_address = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN update_data.contract_address ELSE coins.contract_address END,
						 symbol = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN update_data.symbol ELSE coins.symbol END,
						 symbol_group = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN update_data.symbol_group ELSE coins.symbol_group END,
						 icon_url = CASE WHEN coins.contract_address = '' OR (coins.contract_address != '' AND  %[2]v) THEN update_data.icon_url ELSE coins.icon_url END
			FROM (
				VALUES %[1]v
			) as update_data (
				id, decimals, price_usd, coingecko_coin_id, network,
				name, contract_address, symbol, symbol_group, icon_url
			)
			WHERE coins.id = update_data.id
			RETURNING coins.id
		) DELETE FROM coins_sync_queue WHERE coin_id IN (SELECT id FROM upd)
	`, placeholders, updateFullDataTokens)
	rowsUpdated, err := storage.Exec(ctx, s.db, sql, params...)
	if err != nil {
		return errors.Wrap(err, "failed to update coins data in db from coingecko")
	}
	if rowsUpdated != uint64(len(coins)) {
		err = errors.Errorf("not all coins were updated, expecting %v, updated %v", len(coins), rowsUpdated)
	}
	return errors.Wrap(err, "failed to update coins data in db from coingecko")
}

func (s *coinSync) buildBatchUpdate(now *time.Time, coinsList []*coingecko.Coin, mapping map[string]string) (sql string, params []any) {
	placeholders := make([]string, 0, len(coinsList))
	idx := 2
	params = make([]any, 0, len(coinsList)*10)
	for _, coin := range coinsList {
		params = append(params, generateInternalID(coin, mapping), coin.Decimals, coin.PriceUSD, coin.ID, coin.Network, coin.Name, coin.ContractAddress, coin.Symbol, coin.SymbolGroup(), coin.IconUrl)
		placeholders = append(placeholders, fmt.Sprintf(""+
			"(                  $%[1]v,                $%[2]v::SMALLINT, $%[3]v::NUMERIC, $%[4]v, $%[5]v,         $%[6]v,  $%[7]v,              $%[8]v,  $%[9]v,          $%[10]v)", idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7, idx+8, idx+9))
		idx += 10
	}
	return strings.Join(placeholders, ", \n"), params
}

func (s *coinSync) Printf(format string, args ...interface{}) {
	stdlog.Printf(format, args...)
}
