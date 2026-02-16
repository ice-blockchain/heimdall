-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS trades (
    timestamp TIMESTAMP,
    pair_address SYMBOL CAPACITY 1000000 INDEX,
    contract_address VARCHAR,
    external_address SYMBOL CAPACITY 1000000 INDEX,
    base_price_in_usd DECIMAL(48, 18),
    price_in_usd DECIMAL(48, 18),
    market_cap_usd DECIMAL(48, 18),
    base_amount DECIMAL(76,0),
    amount DECIMAL(76,0),
    trade_type SYMBOL CAPACITY 2 CACHE,
    trader_address VARCHAR,
    transaction_hash VARCHAR
) TIMESTAMP(timestamp) PARTITION BY DAY WAL
DEDUP UPSERT KEYS(timestamp, transaction_hash);
-- Base 15s interval
DROP MATERIALIZED VIEW IF EXISTS ohlcv_15s;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_15s REFRESH IMMEDIATE AS (
    SELECT
    timestamp,
    external_address,
    first( price_in_usd ) AS open,
    max(price_in_usd) AS high,
    min(price_in_usd) AS low,
    last(price_in_usd) AS close,
    sum(price_in_usd) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM trades
    SAMPLE BY 15s ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- Base 1-minute interval
DROP MATERIALIZED VIEW IF EXISTS ohlcv_1m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_1m REFRESH EVERY 1m AS (
    SELECT
    timestamp,
    external_address,
    first( price_in_usd ) AS open,
    max(price_in_usd) AS high,
    min(price_in_usd) AS low,
    last(price_in_usd) AS close,
    sum(price_in_usd) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM trades
    SAMPLE BY 1m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 2-minute interval (based on 15s!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_2m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_2m REFRESH EVERY 1m AS (
    SELECT
    timestamp,
    external_address,
    first( price_in_usd ) AS open,
    max(price_in_usd) AS high,
    min(price_in_usd) AS low,
    last(price_in_usd) AS close,
    sum(price_in_usd) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM trades
    SAMPLE BY 2m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 3-minute interval (based on 1m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_3m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_3m REFRESH EVERY 1m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_1m
    SAMPLE BY 3m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 5-minute interval (based on 1m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_5m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_5m REFRESH EVERY 1m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_1m
    SAMPLE BY 5m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;


-- 10-minute interval (based on 1m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_10m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_10m REFRESH EVERY 5m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_1m
    SAMPLE BY 10m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 15-minute interval (based on 5m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_15m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_15m REFRESH EVERY 5m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_5m
    SAMPLE BY 15m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;


-- 30-minute interval (based on 10m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_30m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_30m REFRESH EVERY 10m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_10m
    SAMPLE BY 30m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 45-minute interval (based on 15m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_45m;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_45m REFRESH EVERY 15m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_15m
    SAMPLE BY 45m ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;


-- 1-hour interval (based on 30m!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_1h;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_1h REFRESH EVERY 30m AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_30m
    SAMPLE BY 1h ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 2-hour interval (based on 1h!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_2h;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_2h REFRESH EVERY 1h AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_1h
    SAMPLE BY 2h ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;

-- 3-hour interval (based on 1h!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_3h;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_3h REFRESH EVERY 1h AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_1h
    SAMPLE BY 3h ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;


-- 4-hour interval (based on 1h!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_4h;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_4h REFRESH EVERY 2h AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_2h
    SAMPLE BY 4h ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 7 DAYS;


-- 1-day interval (based on 4h!)
DROP MATERIALIZED VIEW IF EXISTS ohlcv_24h;
CREATE MATERIALIZED VIEW IF NOT EXISTS ohlcv_24h REFRESH EVERY 4h AS (
    SELECT
    timestamp,
    external_address,
    first(open) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close) AS close,
    sum(volume) AS volume,
    last(market_cap_usd) as market_cap_usd
    FROM ohlcv_4h
    SAMPLE BY 24h ALIGN TO CALENDAR
), INDEX(external_address) PARTITION BY HOUR TTL 60 DAYS;


ALTER TABLE trades DEDUP DISABLE;
ALTER TABLE trades DEDUP ENABLE UPSERT KEYS(timestamp, transaction_hash, trader_address, contract_address);
-- we need to apply manually cuz of issue: https://github.com/questdb/questdb/issues/6750
-- ALTER TABLE trades ADD COLUMN IF NOT EXISTS market_cap_usd DECIMAL(48, 18);

CREATE TABLE IF NOT EXISTS hourly_token_rankings (
    timestamp TIMESTAMP,
    external_address SYMBOL CAPACITY 100000 INDEX,
    contract_address VARCHAR,
    rank INT,
    volume_1h DOUBLE
) TIMESTAMP(timestamp) PARTITION BY MONTH WAL;

CREATE TABLE IF NOT EXISTS token_analytics_snapshots (
    timestamp TIMESTAMP,
    interval_type SYMBOL CAPACITY 10 CACHE,
    launched LONG,
    migrated LONG,
    total_volume DOUBLE
) TIMESTAMP(timestamp) PARTITION BY MONTH WAL;
