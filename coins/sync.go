// SPDX-License-Identifier: ice License 1.0

package coins

import (
	"context"
	"fmt"
	"strings"
	stdlibtime "time"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/coins/internal/coingecko"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func MustStartSyncer(ctx context.Context, cancel context.CancelFunc) Sync {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)

	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	s := &coinSync{
		db:              db,
		shutdown:        db.Close,
		cancel:          cancel,
		cfg:             &cfg,
		coinGeckoClient: coingecko.New(applicationYamlKey),
	}
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
	var consumedTime stdlibtime.Duration
	syncCtx, cancel := context.WithTimeout(context.Background(), coinSyncIterationDuration)
	consumedTime = s.syncCoinBatch(syncCtx)
	cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stdlibtime.After(coinSyncIterationDuration - consumedTime):
			syncCtx, cancel = context.WithTimeout(context.Background(), coinSyncIterationDuration)
			consumedTime = s.syncCoinBatch(syncCtx)
			cancel()
		}
	}
}

func (s *coinSync) syncCoinBatch(ctx context.Context) (consumed stdlibtime.Duration) {
	start := time.Now()
	coinsToSync, err := s.fetchSyncableCoins(ctx)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch syncable coins"))
		return time.Now().Sub(*start.Time)
	}
	coinIDs := coinsToSync[""].CoinGeckoCoinIDs
	delete(coinsToSync, "")
	coinsData, err := s.coinGeckoClient.GetCoins(ctx, coinIDs)
	if err != nil {
		log.Error(errors.Wrapf(err, "failed to fetch market data from coin gecko for coins %#v", coinIDs))
		return time.Now().Sub(*start.Time)
	}
	for network, tokensAddrs := range coinsToSync {
		var batches [][]string
		if len(tokensAddrs.ContractAddresses) > 30 {
			for len(tokensAddrs.ContractAddresses) > 30 {
				batches = append(batches, tokensAddrs.ContractAddresses[:30])
				tokensAddrs.ContractAddresses = tokensAddrs.ContractAddresses[31:]
			}
			batches = append(batches, tokensAddrs.ContractAddresses)
		} else {
			batches = append(batches, tokensAddrs.ContractAddresses)
		}
		for _, b := range batches {
			var tokensData []*coingecko.Coin
			tokensData, err = s.coinGeckoClient.GetTokens(ctx, network, b)
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to fetch market data from coin gecko for tokens on %v network: %#v", network, tokensAddrs))
				return time.Now().Sub(*start.Time)
			}
			coinsData = append(coinsData, tokensData...)
		}
	}
	err = s.updateCoinsData(ctx, start, coinsData)
	return time.Now().Sub(*start.Time)
}

func (s *coinSync) fetchSyncableCoins(ctx context.Context) (map[string]*coinToSync, error) {
	coins, err := storage.Select[coinToSync](ctx, s.db,
		fmt.Sprintf(`SELECT network, 
       		 array_agg(t.coingecko_coin_id) FILTER ( WHERE t.contract_address = '' ) AS coin_ids,
       		 array_agg(t.contract_address) FILTER (WHERE t.contract_address != '')  AS contract_addresses
			 FROM (
				SELECT * FROM coins_sync_queue
				INNER JOIN coins ON coins_sync_queue.coin_id = coins.id
				ORDER BY coins_sync_queue.created_at ASC
				LIMIT %v
			 ) t GROUP BY network`, coinSyncIterationBatchSize),
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

func (s *coinSync) updateCoinsData(ctx context.Context, now *time.Time, coins []*coingecko.Coin) error {
	params := []any{now}
	placeholders, extraParams := buildBatchUpdate(now, coins)
	if len(placeholders) == 0 {
		return nil
	}
	params = append(params, extraParams...)
	sql := fmt.Sprintf(`WITH upd as (
						UPDATE coins SET
						 updated_at = $1,
						 decimals = update_data.decimals,
						 version = (CASE WHEN
											 coins.decimals::SMALLINT != update_data.decimals::SMALLINT OR
											 coins.coingecko_coin_id != update_data.coingecko_coin_id OR
											 coins.network != update_data.network OR
											 coins.name != update_data.name OR
											 coins.contract_address != update_data.contract_address OR
											 coins.symbol != update_data.symbol OR
											 coins.symbol_group != update_data.symbol_group OR
											 coins.icon_url != update_data.icon_url
											 THEN coins.version + 1 ELSE coins.version END),
						 price_usd = update_data.price_usd,
						 coingecko_coin_id = update_data.coingecko_coin_id,
						 network = update_data.network,
						 name = update_data.name,
						 contract_address = update_data.contract_address,
						 symbol = update_data.symbol,
						 symbol_group = update_data.symbol_group,
						 icon_url = update_data.icon_url
			FROM (
				VALUES %v
			) as update_data (
				id, decimals, price_usd, coingecko_coin_id, network,
				name, contract_address, symbol, symbol_group, icon_url
			)
			WHERE coins.id = update_data.id
			RETURNING coins.id
		) DELETE FROM coins_sync_queue WHERE coin_id IN (SELECT id FROM upd)
	`, placeholders)
	rowsUpdated, err := storage.Exec(ctx, s.db, sql, params...)
	if err != nil {
		return errors.Wrap(err, "failed to update coins data in db from coingecko")
	}
	if rowsUpdated != uint64(len(coins)) {
		err = errors.Errorf("not all coins were updated, expecting %v, updated %v", len(coins), rowsUpdated)
	}
	return errors.Wrap(err, "failed to update coins data in db from coingecko")
}

func buildBatchUpdate(now *time.Time, coinsList []*coingecko.Coin) (sql string, params []any) {
	placeholders := make([]string, 0, len(coinsList))
	idx := 2
	params = make([]any, 0, len(coinsList)*10)
	for _, c := range coinsList {
		params = append(params, generateInternalID(c), c.Decimals, c.PriceUSD, c.ID, c.MappedNetwork(), c.Name, c.ContractAddress, c.Symbol, c.SymbolGroup(), c.IconUrl)
		placeholders = append(placeholders, fmt.Sprintf("($%[1]v, $%[2]v::SMALLINT,$%[3]v::NUMERIC, $%[4]v, $%[5]v, $%[6]v, $%[7]v,              $%[8]v,  $%[9]v,          $%[10]v)", idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7, idx+8, idx+9, idx+10))
		idx += 10
	}
	return strings.Join(placeholders, ", "), params
}
