-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS trades (
    timestamp TIMESTAMP,
    pair_address VARCHAR INDEX,
    price DECIMAL(38, 18),
    amount DECIMAL(38, 18),
    type SYMBOL CAPACITY 2 CACHE,
    trader_address VARCHAR,
    transaction_hash LONG256,
) TIMESTAMP(timestamp) PARTITION BY DAY WAL
DEDUP UPSERT KEYS(timestamp, transaction_hash);