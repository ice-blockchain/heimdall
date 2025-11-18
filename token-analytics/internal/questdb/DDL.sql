-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS trades (
                        timestamp TIMESTAMP,
                        symbol SYMBOL,
                        side SYMBOL,
                        price DOUBLE,
                        amount DOUBLE
) TIMESTAMP(timestamp) PARTITION BY DAY WAL
DEDUP UPSERT KEYS(timestamp, symbol);