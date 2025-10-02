-- SPDX-License-Identifier: ice License 1.0
CREATE TABLE IF NOT EXISTS global (
      value TEXT NOT NULL,
      key TEXT PRIMARY KEY
) WITH (FILLFACTOR = 70);

CREATE TABLE IF NOT EXISTS coins (
                                     sync_frequency    INTERVAL NOT NULL,
                                     created_at        TIMESTAMP NOT NULL,
                                     updated_at        TIMESTAMP NOT NULL,
                                     data_updated_at   TIMESTAMP NOT NULL,
                                     version           BIGINT NOT NULL,
                                     coingecko_coin_id TEXT NOT NULL DEFAULT '',
                                     id                TEXT NOT NULL,
                                     network           TEXT NOT NULL,
                                     name              TEXT NOT NULL,
                                     contract_address  TEXT NOT NULL DEFAULT '',
                                     symbol            TEXT NOT NULL,
                                     symbol_group      TEXT NOT NULL,
                                     icon_url          TEXT NOT NULL DEFAULT '',
                                     price_usd         NUMERIC NOT NULL DEFAULT 0,
                                     decimals          SMALLINT NOT NULL,
                                     native            BOOL NOT NULL DEFAULT FALSE,
                                     primary key(id)
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS coins_contract_address_idx ON coins (contract_address);
CREATE INDEX IF NOT EXISTS coins_symbol_group_idx ON coins (symbol_group);
CREATE INDEX IF NOT EXISTS coins_coingecko_coin_id_idx ON coins (coingecko_coin_id);

CREATE OR REPLACE FUNCTION trigger_coins_after_insert_update_store_new_version()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO global (
        value, key
    )
    values (NEW.version, '%[3]v')
    ON CONFLICT(key) DO UPDATE
        SET value = NEW.version
    where global.value::BIGINT < NEW.version;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_coins_after_insert_update_store_new_version
    AFTER INSERT OR UPDATE ON coins
    FOR EACH ROW
EXECUTE FUNCTION trigger_coins_after_insert_update_store_new_version();

CREATE TABLE IF NOT EXISTS coins_sync_queue (
                                                created_at        TIMESTAMP NOT NULL,
                                                coin_id           TEXT NOT NULL REFERENCES coins(id) ON DELETE CASCADE,
                                                primary key(coin_id)
);
CREATE INDEX IF NOT EXISTS coins_sync_queue_created_at_idx ON coins_sync_queue (created_at);
CREATE TABLE IF NOT EXISTS nft_collections (
                                    network           TEXT NOT NULL,
                                    name              TEXT NOT NULL,
                                    description       TEXT NOT NULL,
                                    token_standard    TEXT NOT NULL, -- this is Kind from dfns response
                                    contract_address  TEXT NOT NULL,
                                    symbol            TEXT NOT NULL,
                                    icon_url          TEXT NOT NULL,
                                    primary key(contract_address)
) WITH (FILLFACTOR = 70);

DO $$ BEGIN
    if NOT exists (select 1 from coins where id = '7b471f92-ced2-38b0-e408-88e5d89e8045' and symbol = 'ion') then
        INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version, price_usd, id, coingecko_coin_id, network, name, contract_address, symbol, symbol_group, icon_url, native)
        VALUES            ('%[1]v', now(), now(), now(), 9, 0, %[2]v, '7b471f92-ced2-38b0-e408-88e5d89e8045', 'ion', 'ion', 'Ice Open Network', '', 'ion', 'ion', 'https://cdn.ice.io/online+/assets/coins/ion.svg', true)
        ON CONFLICT (id) DO UPDATE SET
                                       name = 'Ice Open Network',
                                       coingecko_coin_id = 'ion',
                                       symbol = 'ion',
                                       symbol_group = 'ion',
                                       version = coins.version + 1;
    end if;
END$$;


DO $$ BEGIN
    IF NOT exists (select 1 from global where key = '%[3]v') then
        INSERT INTO global(value, key)
        VALUES ((select COALESCE(max(version),0) from coins), '%[3]v')
        ON CONFLICT(key) DO NOTHING;
    end if;
END$$;


DO $$ BEGIN
    IF NOT exists (select * from coins WHERE lower(symbol) = 'pol' and network = 'polygon_pos' and native = true) then
        UPDATE coins SET
                         native = true,
                         version = (select global.value from global where global.key = '%[3]v')::BIGINT + 1
        WHERE lower(symbol) = 'pol' and network = 'polygon_pos';
        UPDATE coins SET
                         native = false,
                         version = (select global.value from global where global.key = '%[3]v')::BIGINT + 1
        WHERE lower(symbol) = 'matic' and network = 'polygon_pos';
    end if;
    UPDATE coins SET
                     version = (select global.value from global where global.key = '%[3]v')::BIGINT + 1,
                     symbol_group = 'tether'
    WHERE symbol_group IN ('binance-bridged-usdt-bnb-smart-chain', 'bridged-usdt');

    UPDATE coins
        SET name = 'WETH (Tron)',
        version = (select global.value from global where global.key = '%[3]v')::BIGINT + 1
        WHERE id = 'b6fd4779-f4d8-49db-be2d-b3bd334f5325';
    -- old ice on bsc
    INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version, price_usd, id, coingecko_coin_id, network, name, contract_address, symbol, symbol_group, icon_url, native)
    VALUES            ('%[1]v', now(), now(), now(), 18, ((select global.value from global where global.key = '%[3]v')::BIGINT + 1), %[2]v, 'c43ae71d-d5f1-1fd1-4dfa-d01af1484655', 'ice', 'bsc', 'Ice Open Network', '0xc335df7c25b72eec661d5aa32a7c2b7b2a1d1874', 'ice', 'ice', 'https://cdn.ice.io/online+/assets/coins/ion.svg', false)
    ON CONFLICT (id) DO UPDATE SET
                                   name = 'Ice Open Network',
                                   coingecko_coin_id = 'ice',
                                   symbol = 'ice',
                                   symbol_group = 'ice',
                                   decimals = 18,
                                   version = ((select global.value from global where global.key = '%[3]v')::BIGINT + 1);
    -- old ice on eth
    INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version, price_usd, id, coingecko_coin_id, network, name, contract_address, symbol, symbol_group, icon_url, native)
    VALUES            ('%[1]v', now(), now(), now(), 18, ((select global.value from global where global.key = '%[3]v')::BIGINT + 1), %[2]v, 'bd3ddc2a-73fc-4c24-3e9b-dbc992fef82d', 'ice', 'eth', 'Ice Open Network', '0x79f05c263055ba20ee0e814acd117c20caa10e0c', 'ice', 'ice', 'https://cdn.ice.io/online+/assets/coins/ion.svg', false)
    ON CONFLICT (id) DO UPDATE SET
                                   name = 'Ice Open Network',
                                   coingecko_coin_id = 'ice',
                                   symbol = 'ice',
                                   symbol_group = 'ice',
                                   decimals = 18,
                                   version = ((select global.value from global where global.key = '%[3]v')::BIGINT + 1);
    -- old ice on solana
    INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version, price_usd, id, coingecko_coin_id, network, name, contract_address, symbol, symbol_group, icon_url, native)
    VALUES            ('%[1]v', now(), now(), now(), 8, ((select global.value from global where global.key = '%[3]v')::BIGINT + 1), %[2]v, '742bd2b4-6f9b-44c5-e13c-7bd8cd43e001', 'ice', 'solana', 'Ice Open Network', 'E9aPbhb5xRVGP2L6qJixfJC5qWAzECpUFUxnGx3wUiND', 'ice', 'ice', 'https://cdn.ice.io/online+/assets/coins/ion.svg', false)
    ON CONFLICT (id) DO UPDATE SET
                                   name = 'Ice',
                                   coingecko_coin_id = 'ice',
                                   symbol = 'ice',
                                   symbol_group = 'ice',
                                   decimals = 8,
                                   version = ((select global.value from global where global.key = '%[3]v')::BIGINT + 1);
    -- old ice on arbitrum
    INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version, price_usd, id, coingecko_coin_id, network, name, contract_address, symbol, symbol_group, icon_url, native)
    VALUES            ('%[1]v', now(), now(), now(), 18, ((select global.value from global where global.key = '%[3]v')::BIGINT + 1), %[2]v, 'bce57663-8fb0-6d41-c6f1-c03c0c39a3ad', 'ice', 'arbitrum', 'Ice Open Network', '0xAB8EBCC9eecc20Bd30c7b75c7b4e8fcCcFBf01aB', 'ice', 'ice', 'https://cdn.ice.io/online+/assets/coins/ion.svg', false)
    ON CONFLICT (id) DO UPDATE SET
                                   name = 'Ice',
                                   coingecko_coin_id = 'ice',
                                   symbol = 'ice',
                                   symbol_group = 'ice',
                                   decimals = 18,
                                   version = ((select global.value from global where global.key = '%[3]v')::BIGINT + 1);
    -- snow
    INSERT INTO coins (sync_frequency, created_at, updated_at, data_updated_at, decimals, version, price_usd, id, coingecko_coin_id, network, name, contract_address, symbol, symbol_group, icon_url, native)
    VALUES            ('%[1]v', now(), now(), now(), 18, ((select global.value from global where global.key = '%[3]v')::BIGINT + 1), 0.0000000005294336947, 'ca5a9f29-06ef-39a2-09ef-3d3942207110', 'snowman', 'eth', 'Snowman', '0xd1f3d2f5c12a205fc912358878b089eae48a557f', 'snow', 'snowman', 'https://cdn.ice.io/online+/assets/coins/ion.svg', false)
    ON CONFLICT (id) DO UPDATE SET
                                   name = 'Snowman',
                                   coingecko_coin_id = 'snowman',
                                   symbol = 'snow',
                                   symbol_group = 'snowman',
                                   version = ((select global.value from global where global.key = '%[3]v')::BIGINT + 1);
    DELETE FROM coins where network = 'ftm';
END$$;

UPDATE coins SET
                 version = (select global.value from global where global.key = '%[3]v')::BIGINT + 1,
                 icon_url = (CASE
                                 WHEN coingecko_coin_id = 'icecream' THEN 'https://coin-images.coingecko.com/coins/images/26237/large/icecream.png?1696525321'
                                 WHEN coingecko_coin_id = 'iron-finance' THEN 'https://coin-images.coingecko.com/coins/images/17024/large/ice_logo.jpg?1696516587'
                                 WHEN coingecko_coin_id = 'alligator-alcatraz' THEN 'https://coin-images.coingecko.com/coins/images/66962/large/ICE.png?1751266097'
                                 WHEN coingecko_coin_id = 'ice-bucket-challenge' THEN 'https://coin-images.coingecko.com/coins/images/55313/large/icebucket.png?1745368086'
                                 WHEN coingecko_coin_id = 'decentral-games-ice' THEN 'https://coin-images.coingecko.com/coins/images/18110/large/ice-poker.png?1696517614'
                                 WHEN coingecko_coin_id = 'ice-token' THEN 'https://coin-images.coingecko.com/coins/images/14586/large/ice.png?1696514266'
                                 WHEN coingecko_coin_id = 'iceleia' THEN 'https://static.arkhamintelligence.com/tokens/iceleia.png'
                                 ELSE coins.icon_url END)
WHERE lower(symbol) = 'ice';

UPDATE coins SET
                 version = (select global.value from global where global.key = '%[3]v')::BIGINT + 1,
                 decimals = 10
where network = 'polkadot' and lower(symbol) = 'dot' and decimals > 10;