// SPDX-License-Identifier: ice License 1.0

package coins

import (
	"context"
	"crypto/md5"
	"fmt"
	"math"
	"slices"
	"strings"
	stdlibtime "time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/ice-blockchain/heimdall/coins/internal/coingecko"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func New(ctx context.Context) Coins {

	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	c := coinsRepository{
		cfg:                &cfg,
		coinGeckoClient:    coingecko.New(applicationYamlKey),
		nftCoinGeckoClient: coingecko.New("nfts"),
	}
	iceCoin, err := c.coinGeckoClient.GetCoins(ctx, []string{DefaultWalletViewCoinSymbolGroup})
	log.Panic(errors.Wrapf(err, "failed to sync ice price from coin gecko on startup"))
	if len(iceCoin) == 0 {
		log.Panic(errors.New("ice coin not found on coin gecko"))
	}
	db := storage.MustConnect(ctx, fmt.Sprintf(ddl, syncFrequency(c.cfg, DefaultWalletViewCoinSymbolGroup), iceCoin[0].PriceUSD, keyCoinsMaxVersion), applicationYamlKey)
	c.db = db
	c.shutdown = db.Close
	if c.needToSyncAllCoins(ctx) {
		log.Panic(errors.Wrapf(c.syncAllCoins(ctx), "failed to sync all coin gecko coins on startup"))
	}

	return &c
}

func (c *coinsRepository) Close() error {
	return errors.Wrapf(c.shutdown(), "failed to close coins repository")
}

func (c *coinsRepository) GetFees(network string) *Fee {
	if fee, hasFeeOverride := c.cfg.Fees[strings.ToLower(network)]; hasFeeOverride {
		return &fee
	}
	return nil
}

func (c *coinsRepository) HealthCheck(ctx context.Context) error {
	if err := c.db.Ping(ctx); err != nil {
		return errors.Wrap(err, "[health-check] failed to ping DB")
	}
	return nil
}

func (c *coinsRepository) needToSyncAllCoins(ctx context.Context) bool {
	ex, err := storage.Select[struct {
		Exist int
	}](ctx, c.db, "SELECT 1 as exist FROM coins LIMIT 7;")
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		log.Panic(errors.Wrapf(err, "failed to check any coin existence"))
	}
	if len(ex) <= 6 || storage.IsErr(err, storage.ErrNotFound) {
		return true
	}
	return false
}

func (c *coinsRepository) syncAllCoins(ctx context.Context) error {
	now := time.Now()
	log.Debug("Getting all coins from coin gecko...")
	coinsList, err := c.coinGeckoClient.ListCoins(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to list all coins from coin gecko")
	}
	if len(coinsList) == 0 {
		return nil
	}
	_, paramsPerCoin := c.buildInsertBatchForCoins(now, []*coingecko.Coin{coinsList[0]})
	var batches [][]*coingecko.Coin
	total := len(coinsList)
	if len(coinsList)*len(paramsPerCoin) >= 65535 {
		for len(coinsList)*len(paramsPerCoin) >= 65535 {
			batches = append(batches, coinsList[:65535/len(paramsPerCoin)])
			coinsList = coinsList[65535/len(paramsPerCoin)+1:]
		}
		batches = append(batches, coinsList)
	} else {
		batches = append(batches, coinsList)
	}
	var errGroup errgroup.Group
	for _, batch := range batches {
		errGroup.Go(func() error {
			log.Debug(fmt.Sprintf("Inserting %v coins of %v...", len(batch), total))
			placeholders, params := c.buildInsertBatchForCoins(now, batch)
			sql := fmt.Sprintf(`
			INSERT INTO coins(created_at, updated_at, data_updated_at, sync_frequency, decimals, version, id, network, name, symbol, symbol_group, contract_address, coingecko_coin_id, price_usd, icon_url, native) VALUES 		      %[1]v ON CONFLICT(id) DO NOTHING;`,
				placeholders)
			_, err = storage.Exec(ctx, c.db, sql, params...)
			if err != nil {
				return errors.Wrapf(err, "failed to sync all coins to db")
			}
			log.Debug(fmt.Sprintf("Inserted %v coins of %v...", len(batch), total))

			return nil
		})
	}

	return errGroup.Wait()
}
func (c *coinsRepository) buildInsertBatchForCoins(now *time.Time, coinsList []*coingecko.Coin) (sql string, params []any) {
	params = []any{now}
	placeholders := make([]string, 0, len(coinsList))
	idx := 2
	for _, coinItem := range coinsList {
		params = append(params, syncFrequency(c.cfg, coinItem.ID), coinItem.Decimals, generateInternalID(coinItem, nil), coinItem.Network, coinItem.Name, coinItem.Symbol, coinItem.SymbolGroup(), coinItem.ContractAddress, coinItem.ID, coinItem.PriceUSD, coinItem.IconUrl, coinItem.Native)
		placeholders = append(placeholders, fmt.Sprintf("($1,$1,$1, $%[1]v::INTERVAL, $%[2]v, COALESCE((select value from global where key = '%[1]v')::BIGINT,0), $%[3]v,$%[4]v, $%[5]v, $%[6]v, $%[7]v, $%[8]v, $%[9]v, $%[10]v, $%[11]v, $%[12]v)", idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7, idx+8, idx+9, idx+10, idx+11))
		idx += 12
	}
	return strings.Join(placeholders, ", "), params
}

func generateInternalID(coin *coingecko.Coin, mapping map[string]string) string {
	if coin.ID == "" && len(mapping) > 0 {
		coin.ID = mapping[coin.Network+":@:@:"+coin.ContractAddress]
	}
	if coin.Network == "" && len(mapping) > 0 {
		nw, hasNetwork := mapping[coin.ID]
		if hasNetwork {
			coin.Network = nw
			spl := strings.Split(nw, ":@:@:")
			if len(spl) == 2 {
				coin.Network = spl[0]
				if coin.ContractAddress == "" {
					coin.ContractAddress = spl[1]
				}
			}
		}
	}
	hash := md5.Sum([]byte(coin.Network + coin.ContractAddress + coin.ID))
	id, _ := uuid.FromBytes(hash[:])
	return id.String()
}

func (c *coinsRepository) Import(ctx context.Context, network, contractAddress string) (coin *Coin, retErr error) {
	now := time.Now()
	existingCoin, err := c.getCoinByContractAddress(ctx, contractAddress)
	if err != nil {
		if errors.Is(err, ErrNotFound) || (existingCoin != nil && existingCoin.PriceUSD == 0) {
			var token *coingecko.Coin
			token, err = c.coinGeckoClient.GetToken(ctx, network, contractAddress)
			if err != nil && !errors.Is(err, coingecko.ErrNotFound) {
				return nil, errors.Wrapf(err, "failed to fetch token info from coin gecko")
			}
			if token == nil {
				// 404.
				retErr = ErrNotFound
				token = &coingecko.Coin{
					Network:         network,
					ContractAddress: contractAddress,
				}
			}
			existingCoin, err = c.upsertCoin(ctx, now, token)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to import coin")
			}
		} else {
			return nil, errors.Wrapf(err, "failed to fetch coin by contract address %v", contractAddress)
		}
	}
	return &Coin{
		ID:              existingCoin.ID,
		Name:            existingCoin.Name,
		Symbol:          existingCoin.Symbol,
		SymbolGroup:     existingCoin.SymbolGroup,
		Network:         existingCoin.Network,
		ContractAddress: existingCoin.ContractAddress,
		IconURL:         existingCoin.IconUrl,
		PriceUSD:        existingCoin.PriceUSD,
		SyncFrequency:   existingCoin.SyncFrequency,
		Decimals:        existingCoin.Decimals,
		Native:          existingCoin.Native,
	}, retErr
}

func (c *coinsRepository) getCoinByContractAddress(ctx context.Context, contractAddress string) (*coin, error) {
	coinObj, err := storage.Get[coin](ctx, c.db, "SELECT * FROM coins WHERE contract_address = $1", contractAddress)
	if err != nil && !storage.IsErr(err, storage.ErrNotFound) {
		return nil, errors.Wrapf(err, "failed to get coin by contract address %v", contractAddress)
	}
	return coinObj, err
}

func MapNetworkToCoinGecko(network string) (string, error) {
	return coingecko.MapNetwork(network)
}
func MapNetworkFromCoinGecko(cgNetwork, symbolGroup string) (mappedNetwork string, priority bool, err error) {
	network, err := coingecko.MapNetworkFromCoinGecko(cgNetwork)
	if err != nil {
		return "", false, err
	}
	priority = false
	if slices.Contains(network.PrioritizedCoins, symbolGroup) {
		priority = true
	}
	return network.ID, priority, nil
}

func (c *coinsRepository) upsertCoin(ctx context.Context, now *time.Time, tok *coingecko.Coin) (*coin, error) {
	sql := fmt.Sprintf(`
	INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version,                             price_usd, id, coingecko_coin_id,
		network, name, contract_address, symbol, symbol_group, icon_url, native) VALUES (
	$2,             $1,         $1,         $1,          $3,     (select value from global where key = '%[1]v')::BIGINT,      $4,        $5,  $6,
		$7,      $8,    $9,              $10,   $11,          $12,   false
		)
		ON CONFLICT (id) DO UPDATE SET
		sync_frequency = excluded.sync_frequency,
			updated_at = excluded.updated_at,
			decimals = excluded.decimals,
			version = (CASE WHEN
		coins.decimals != excluded.decimals OR
		coins.coingecko_coin_id != excluded.coingecko_coin_id OR
		coins.network != excluded.network OR
		coins.name != excluded.name OR
		coins.contract_address != excluded.contract_address OR
		coins.symbol != excluded.symbol OR
		coins.symbol_group != excluded.symbol_group OR
		coins.icon_url != excluded.icon_url
		THEN (select value from global where key = '%[1]v')::BIGINT + 1 ELSE coins.version END),
			price_usd = excluded.price_usd,
				coingecko_coin_id = excluded.coingecko_coin_id,
				network = excluded.network,
				name = excluded.name,
				contract_address = excluded.contract_address,
				symbol = excluded.symbol,
				symbol_group = excluded.symbol_group,
				icon_url = excluded.icon_url
			RETURNING *;`, keyCoinsMaxVersion)

	updated, err := storage.ExecOne[coin](ctx, c.db, sql, now, syncFrequency(c.cfg, tok.ID), tok.Decimals, tok.PriceUSD, generateInternalID(tok, nil),
		tok.ID, tok.Network, tok.Name, tok.ContractAddress, tok.Symbol, tok.SymbolGroup(), tok.IconUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to upsert token data %+v", tok)
	}
	return updated, nil
}

func (c *coinsRepository) GetAllCoins(ctx context.Context) (uint64, []*SymbolGroupWithCoins, error) {
	allCoins, err := storage.Select[coin](ctx, c.db, fmt.Sprintf(`SELECT 
		'00:00:00'::INTERVAL as sync_frequency,
		now() as created_at,
		now() as updated_at,
		now() as data_updated_at,
		coalesce((select value from global where key = 'coins_max_version')::BIGINT,0) as version,
		'' as id,
		'' as coingecko_coin_id,
		'' as network,
		'' as name,
		'' as contract_address,
		'' as symbol,
		'' as symbol_group,
		'' as icon_url,
		0 as price_usd,
		0 as decimals,
		false as native
	FROM coins
 	UNION ALL (SELECT * FROM coins WHERE coingecko_coin_id != '');`, keyCoinsMaxVersion))
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to list all coins from db")
	}
	if len(allCoins) <= 1 {
		if err = c.syncAllCoins(ctx); err != nil {
			return 0, nil, errors.Wrapf(err, "empty coins on db, and failed to sync initial from coingecko")
		}
		allCoins, err = storage.Select[coin](ctx, c.db, `SELECT * FROM coins WHERE symbol_group != ''`)
		if err != nil {
			return 0, nil, errors.Wrapf(err, "failed to list all coins from db")
		}
	}
	version := allCoins[0].Version
	allCoins = allCoins[1:]
	groups := map[string][]*Coin{}
	for _, c := range allCoins {
		network, priority, err := MapNetworkFromCoinGecko(c.Network, c.SymbolGroup)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to map network %v for coin %v", c.Network, &c))
			continue
		}
		groups[c.SymbolGroup] = append(groups[c.SymbolGroup], &Coin{
			ID:              c.ID,
			Name:            c.Name,
			Symbol:          c.Symbol,
			SymbolGroup:     c.SymbolGroup,
			Network:         network,
			ContractAddress: c.ContractAddress,
			IconURL:         c.IconUrl,
			PriceUSD:        c.PriceUSD,
			Decimals:        c.Decimals,
			SyncFrequency:   c.SyncFrequency,
			Version:         &c.Version,
			Native:          c.Native,
			Prioritized:     priority,
		})
	}
	res := make([]*SymbolGroupWithCoins, 0, len(groups))
	for symbolGroup, coins := range groups {
		res = append(res, &SymbolGroupWithCoins{
			SymbolGroup: symbolGroup,
			Coins:       coins,
		})
	}
	return version, res, nil
}

func (c *coinsRepository) GetVersionedCoins(ctx context.Context, userID string, knownVersion *int) (latestVersion uint64, coinDiff []*Coin, err error) {
	version := initialVersion
	if knownVersion != nil {
		version = (*knownVersion + 1)
	}
	newCoins, err := storage.Select[coin](ctx, c.db, `SELECT * FROM coins WHERE ($1 = '' OR id IN (SELECT (unnest(coins)::coin_mapping).coinId FROM wallet_views WHERE user_id = $1)) AND version >= $2`, userID, version)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "failed to select coins by version %v", version)
	}
	if len(newCoins) == 0 {
		return 0, nil, ErrNotChanged
	}
	maxVersion := newCoins[0].Version
	for _, c := range newCoins {
		maxVersion = uint64(math.Max(float64(maxVersion), float64(c.Version)))
		network, priority, err := MapNetworkFromCoinGecko(c.Network, c.SymbolGroup)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to get versioned coins due to unmapped network %v %v", c.Network, c))
		}
		coinDiff = append(coinDiff, &Coin{
			ID:              c.ID,
			Name:            c.Name,
			Symbol:          c.Symbol,
			SymbolGroup:     c.SymbolGroup,
			Network:         network,
			ContractAddress: c.ContractAddress,
			IconURL:         c.IconUrl,
			PriceUSD:        c.PriceUSD,
			SyncFrequency:   c.SyncFrequency,
			Decimals:        c.Decimals,
			Version:         &c.Version,
			Native:          c.Native,
			Prioritized:     priority,
		})
	}
	return maxVersion, coinDiff, nil
}

func (c *coinsRepository) SyncCoins(ctx context.Context, symbolGroups []string) ([]*Coin, error) {
	now := time.Now()
	coinsList, err := storage.Select[coin](ctx, c.db, `SELECT * from coins where symbol_group = ANY($1)`, symbolGroups)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to select coins for symbol groups %#v", symbolGroups)
	}
	bySymbolGroupAndNetwork := make(map[string]*Coin)
	coinsToSync := make([]string, len(coinsList))
	for _, coin := range coinsList {
		network, priority, err := MapNetworkFromCoinGecko(coin.Network, coin.SymbolGroup)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to map network %v for coin %+v", coin.Network, coin))
			continue
		}
		bySymbolGroupAndNetwork[coin.SymbolGroup+coin.Network] = &Coin{
			Symbol:        coin.Symbol,
			Network:       network,
			SymbolGroup:   coin.SymbolGroup,
			PriceUSD:      coin.PriceUSD,
			SyncFrequency: coin.SyncFrequency,
			Decimals:      coin.Decimals,
			Native:        coin.Native,
			Prioritized:   priority,
		}
		needSync := now.Sub(*coin.UpdatedAt.Time) >= coin.SyncFrequency || (now.Sub(*coin.UpdatedAt.Time) >= 24*stdlibtime.Hour && coin.PriceUSD == 0)
		if needSync {
			coinsToSync = append(coinsToSync, coin.ID)
		}
	}
	if len(coinsToSync) > 0 {
		if err = c.requestCoinsSync(ctx, now, coinsToSync); err != nil {
			return nil, errors.Wrapf(err, "failed to request sync of outdated coins: %#v", coinsToSync)
		}
	}
	res := make([]*Coin, 0, len(bySymbolGroupAndNetwork))
	for _, coin := range bySymbolGroupAndNetwork {
		res = append(res, coin)
	}
	return res, nil
}
func (c *coinsRepository) requestCoinsSync(ctx context.Context, now *time.Time, coinIDs []string) error {
	_, err := storage.Exec(ctx, c.db, `INSERT INTO coins_sync_queue 
															SELECT $1, id from coins where id = ANY($2)
															AND (($1::TIMESTAMP - coins.updated_at) >= coins.sync_frequency 
															OR (($1::TIMESTAMP - coins.updated_at) >= '24 hours'::INTERVAL AND coins.price_usd = 0))
                                                            ON CONFLICT(coin_id) DO NOTHING;`, now, coinIDs)

	return errors.Wrapf(err, "failed to insert into sync queue")
}

func (c *coinsRepository) GetCoinsOfSymbolGroup(ctx context.Context, symbolGroups []string) ([]*Coin, error) {
	coinsList, err := storage.Select[coin](ctx, c.db, `SELECT * from coins where symbol_group = ANY($1)`, symbolGroups)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to select coins for symbol groups %#v", symbolGroups)
	}
	res := make([]*Coin, 0, len(coinsList))
	for _, c := range coinsList {
		network, priority, err := MapNetworkFromCoinGecko(c.Network, c.SymbolGroup)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to get coins of symbol group due to unmapped network %v %v", c.Network, c))
			continue
		}
		res = append(res, &Coin{
			ID:              c.ID,
			Name:            c.Name,
			Symbol:          c.Symbol,
			SymbolGroup:     c.SymbolGroup,
			Network:         network,
			ContractAddress: c.ContractAddress,
			IconURL:         c.IconUrl,
			PriceUSD:        c.PriceUSD,
			SyncFrequency:   c.SyncFrequency,
			Decimals:        c.Decimals,
			Native:          c.Native,
			Prioritized:     priority,
		})
	}
	return res, nil
}

func syncFrequency(cfg *config, coinGeckoCoinID string) stdlibtime.Duration {
	if freq, hasFreq := cfg.SyncFrequency[coinGeckoCoinID]; hasFreq {
		return freq
	}

	return cfg.DefaultSyncFrequency
}

func IsTestnet(network string) bool {
	return coingecko.IsTestnet(network)
}

func (c *coinsRepository) GetAllNetworks() []*Network {
	return c.coinGeckoClient.GetAllNetworks()
}

func (c *coinsRepository) GetNativeCoinForNetwork(ctx context.Context, network string) (*Coin, error) {
	cgNetwork, err := MapNetworkToCoinGecko(network)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to map network %v to coin gecko", network)
	}
	nativeCoin, err := storage.Get[coin](ctx, c.db, `SELECT * from coins where network = $1 and native;`, cgNetwork)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to select native coin for network %v", network)
	}
	network, priority, err := MapNetworkFromCoinGecko(nativeCoin.Network, nativeCoin.SymbolGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get coins of symbol group due to unmapped network %v %+v", nativeCoin.Network, c)
	}
	return &Coin{
		ID:              nativeCoin.ID,
		Name:            nativeCoin.Name,
		Symbol:          nativeCoin.Symbol,
		SymbolGroup:     nativeCoin.SymbolGroup,
		Network:         network,
		ContractAddress: nativeCoin.ContractAddress,
		IconURL:         nativeCoin.IconUrl,
		PriceUSD:        nativeCoin.PriceUSD,
		SyncFrequency:   nativeCoin.SyncFrequency,
		Decimals:        nativeCoin.Decimals,
		Native:          nativeCoin.Native,
		Prioritized:     priority,
	}, nil
}
