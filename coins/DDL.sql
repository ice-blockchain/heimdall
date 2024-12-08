-- SPDX-License-Identifier: ice License 1.0

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
                                     primary key(id)
);

CREATE INDEX IF NOT EXISTS coins_contract_address_idx ON coins (contract_address);
CREATE INDEX IF NOT EXISTS coins_symbol_group_idx ON coins (symbol_group);

CREATE TABLE IF NOT EXISTS coins_sync_queue (
                                                created_at        TIMESTAMP NOT NULL,
                                                coin_id           TEXT NOT NULL REFERENCES coins(id) ON DELETE CASCADE,
                                                primary key(coin_id)
);
CREATE INDEX IF NOT EXISTS coins_sync_queue_created_at_idx ON coins_sync_queue (created_at);

CREATE TABLE IF NOT EXISTS nfts (
                                    network           TEXT NOT NULL,
                                    token_id          TEXT NOT NULL,
                                    name              TEXT NOT NULL,
                                    description       TEXT NOT NULL,
                                    token_standard    TEXT NOT NULL, -- this is Kind from dfns response
                                    contract_address  TEXT NOT NULL,
                                    symbol            TEXT NOT NULL,
                                    icon_url          TEXT NOT NULL,
                                    primary key(contract_address)
);