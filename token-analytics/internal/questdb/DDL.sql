-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS trades (
    timestamp TIMESTAMP,
    pair_address SYMBOL CAPACITY 1000000 INDEX,
    contract_address VARCHAR,
    ion_connect_address SYMBOL CAPACITY 1000000 INDEX,
    base_price LONG,
    base_amount DECIMAL(76,0),
    amount DECIMAL(76,0),
    trade_type SYMBOL CAPACITY 2 CACHE,
    trader_address VARCHAR,
    transaction_hash VARCHAR
) TIMESTAMP(timestamp) PARTITION BY DAY WAL
DEDUP UPSERT KEYS(timestamp, transaction_hash);