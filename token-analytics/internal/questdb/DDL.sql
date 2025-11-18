-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS trades (
    timestamp TIMESTAMP,
    pair_address SYMBOL CAPACITY 1000000 INDEX,
    contract_address VARCHAR,
    content_ion_connect_address SYMBOL CAPACITY 1000000 INDEX,
    price LONG,
    amount LONG256,
    trade_type SYMBOL CAPACITY 2 CACHE,
    trader_address VARCHAR,
    transaction_hash VARCHAR
) TIMESTAMP(timestamp) PARTITION BY DAY WAL
DEDUP UPSERT KEYS(timestamp, transaction_hash);