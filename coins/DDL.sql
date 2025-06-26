-- SPDX-License-Identifier: ice License 1.0
CREATE TABLE IF NOT EXISTS global (
      value BIGINT NOT NULL,
      key TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS coins (
                                     sync_frequency    INTERVAL NOT NULL,
                                     created_at        TIMESTAMP NOT NULL,
                                     updated_at        TIMESTAMP NOT NULL,
                                     data_updated_at   TIMESTAMP NOT NULL,
                                     decimals          SMALLINT NOT NULL,
                                     version           BIGINT NOT NULL,
                                     price_usd         NUMERIC NOT NULL DEFAULT 0,
                                     id                TEXT NOT NULL,
                                     coingecko_coin_id TEXT NOT NULL DEFAULT '',
                                     network           TEXT NOT NULL,
                                     name              TEXT NOT NULL,
                                     contract_address  TEXT NOT NULL DEFAULT '',
                                     symbol            TEXT NOT NULL,
                                     symbol_group      TEXT NOT NULL,
                                     icon_url          TEXT NOT NULL DEFAULT '',
                                     native            BOOL NOT NULL DEFAULT FALSE,
                                     primary key(id)
);

CREATE INDEX IF NOT EXISTS coins_contract_address_idx ON coins (contract_address);
CREATE INDEX IF NOT EXISTS coins_symbol_group_idx ON coins (symbol_group);
CREATE INDEX IF NOT EXISTS coins_coingecko_coin_id_idx ON coins (coingecko_coin_id);

ALTER TABLE coins ADD COLUMN IF NOT EXISTS native BOOL NOT NULL DEFAULT FALSE;

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
ALTER TABLE IF EXISTS nfts RENAME TO nft_collections;
CREATE TABLE IF NOT EXISTS nft_collections (
                                    network           TEXT NOT NULL,
                                    name              TEXT NOT NULL,
                                    description       TEXT NOT NULL,
                                    token_standard    TEXT NOT NULL, -- this is Kind from dfns response
                                    contract_address  TEXT NOT NULL,
                                    symbol            TEXT NOT NULL,
                                    icon_url          TEXT NOT NULL,
                                    primary key(contract_address)
);

ALTER TABLE nft_collections DROP COLUMN IF EXISTS token_id;
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
