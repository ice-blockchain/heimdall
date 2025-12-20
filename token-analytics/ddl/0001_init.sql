-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'usd_amount') THEN
        CREATE DOMAIN usd_amount AS NUMERIC(48, 18);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'uint256') THEN
        CREATE DOMAIN uint256 AS NUMERIC(78, 0);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'platform_type') THEN
        CREATE TYPE platform_type AS ENUM ('xcom', 'ionconnect');
    END IF;
END $$;

CREATE OR REPLACE FUNCTION to_int256(val NUMERIC)
    RETURNS NUMERIC AS $$
DECLARE
    limit_val NUMERIC := 57896044618658097711785492504343953926634992332820282019728792003956564819968; -- 2^255
    mod_val NUMERIC   := 115792089237316195423570985008687907853269984665640564039457584007913129639936; -- 2^256
BEGIN
    IF val >= limit_val THEN
        RETURN val - mod_val;
    ELSE
        RETURN val;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS users
(
    created_at           TIMESTAMP NOT NULL,
    updated_at           TIMESTAMP NOT NULL,
    id                   TEXT NOT NULL,
    master_pubkey        TEXT NOT NULL,
    content_author_id    TEXT NOT NULL,
    external_address     TEXT UNIQUE,
    username             TEXT NOT NULL,
    display_name         TEXT,
    avatar               TEXT,
    lookup               TEXT NOT NULL DEFAULT '',
    ion_connect_relays   TEXT[],
    verified             BOOLEAN NOT NULL DEFAULT false,
    platform_group       platform_type,
    PRIMARY KEY(content_author_id)
);

CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at);
CREATE INDEX IF NOT EXISTS idx_users_external_address ON users (external_address);
CREATE INDEX IF NOT EXISTS idx_users_content_author_id_lower ON users (LOWER(content_author_id));
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_users_lookup_gist ON users USING gist (lookup gist_trgm_ops);

CREATE TABLE IF NOT EXISTS transactions
(
    i                           BIGINT generated always as identity NOT NULL UNIQUE,
    block_timestamp             TIMESTAMP NOT NULL,
    gas                         BIGINT NOT NULL,
    gas_price                   BIGINT NOT NULL,
    nonce                       BIGINT NOT NULL,
    block_number                BIGINT NOT NULL,
    max_fee_per_gas             BIGINT,
    max_priority_fee_per_gas    BIGINT,
    transaction_index           BIGINT,
    chain_id                    TEXT NOT NULL,
    transaction_hash            TEXT NOT NULL,
    block_hash                  TEXT NOT NULL,
    to_address                  TEXT NOT NULL,
    value                       TEXT NOT NULL,
    from_address                TEXT NOT NULL,
    transaction_type            TEXT,
    y_parity                    TEXT,
    input                       TEXT,
    PRIMARY KEY (transaction_hash)
);
CREATE INDEX IF NOT EXISTS idx_transactions_from_address ON transactions (from_address);

CREATE TABLE IF NOT EXISTS tx_logs
(
    ingested_at         TIMESTAMP NOT NULL DEFAULT NOW(),
    processed_at        TIMESTAMP,
    block_number        BIGINT NOT NULL,
    log_index           BIGINT NOT NULL,
    transaction_hash    TEXT NOT NULL REFERENCES transactions(transaction_hash) DEFERRABLE INITIALLY DEFERRED,
    stream_id           TEXT NOT NULL,
    address             TEXT NOT NULL,
    topic0              TEXT NOT NULL,
    data                TEXT,
    topics              TEXT[],
    removed             BOOLEAN NOT NULL,
    primary key (transaction_hash, log_index)
);

CREATE TABLE IF NOT EXISTS smart_contract_transactions (
    from_block_number BIGINT,
    to_block_number   BIGINT,
    network           TEXT,
    stream_id         TEXT,
    data              JSONB,
    PRIMARY KEY (from_block_number,to_block_number,network)
);

CREATE INDEX IF NOT EXISTS smart_contract_transactions_to_block_number_idx ON smart_contract_transactions (to_block_number);

CREATE OR REPLACE FUNCTION trigger_move_incoming_logs()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO transactions (
        chain_id,
        block_number,
        transaction_hash,
        transaction_index,
        gas,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        nonce,
        block_hash,
        to_address,
        transaction_type,
        value,
        y_parity,
        input,
        from_address,
        block_timestamp
    ) SELECT
            transaction_data->>'chainId',
            (transaction_data->>'blockNumber')::BIGINT,
            transaction_data->>'hash',
            (transaction_data->>'transactionIndex')::BIGINT,
            (transaction_data->>'gas')::BIGINT,
            (transaction_data->>'gasPrice')::BIGINT,
            (transaction_data->>'maxFeePerGas')::BIGINT,
            (transaction_data->>'maxPriorityFeePerGas')::BIGINT,
            (transaction_data->>'nonce')::BIGINT,
            transaction_data->>'blockHash',
            transaction_data->>'to',
            transaction_data->>'type',
            (transaction_data->>'value')::BIGINT,
            (transaction_data->>'yParity')::BIGINT,
            transaction_data->>'input',
            transaction_data->>'from',
            to_timestamp((transaction_data->>'blockTimestamp')::BIGINT)
         FROM jsonb_array_elements(NEW.data -> 'transactions') as transaction_data
    ON CONFLICT(transaction_hash) DO NOTHING;

    INSERT INTO tx_logs(stream_id, address, topics, topic0, data, block_number, transaction_hash, log_index, removed)
    (SELECT
              NEW.data ->> 'stream',
              log_elem->>'address' as address,
              (SELECT t.topics from jsonb_to_record(log_elem) as t (topics TEXT[])) AS topics,
              (log_elem->'topics'->>0) as topic0,
              log_elem->>'data' as data,
              (tx_data->>'blockNumber')::BIGINT as block_number,
              tx_data->>'hash' as transaction_hash,
              (log_elem->>'logIndex')::BIGINT as log_index,
              (log_elem->>'removed')::BOOLEAN as removed
              FROM jsonb_array_elements(NEW.data -> 'transactions') as tx_data,
                   jsonb_array_elements(tx_data -> 'logs') as log_elem)
    ON CONFLICT (transaction_hash, log_index) DO NOTHING;
    DELETE FROM smart_contract_transactions WHERE to_block_number <= NEW.to_block_number;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_move_incoming_logs
    AFTER INSERT ON smart_contract_transactions
    FOR EACH ROW
EXECUTE FUNCTION trigger_move_incoming_logs();

CREATE TABLE IF NOT EXISTS streams (
    contract_address TEXT NOT NULL,
    stream_id TEXT,
    name TEXT,
    created_at TIMESTAMP,
    PRIMARY KEY (contract_address)
);

CREATE TABLE IF NOT EXISTS tokens (
    created_at                      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMP NOT NULL DEFAULT NOW(),
    contract_address                TEXT NOT NULL,
    external_address                TEXT NOT NULL UNIQUE,
    platform                        platform_type NOT NULL,
    ticker                          TEXT NOT NULL,
    total_supply                    uint256 NOT NULL,
    content_author_id               TEXT,
    "type"                          TEXT NOT NULL, -- profile/post/video/article
    base_token                      TEXT,
    pair_id                         TEXT,
    market_cap                      uint256 DEFAULT 0,
    market_cap_usd                  usd_amount DEFAULT 0,
    price_usd                       usd_amount DEFAULT 0,
    liquidity_usd                   usd_amount DEFAULT 0,
    holders_count                   BIGINT DEFAULT 0,
    bonding_curve_current_amount    uint256 DEFAULT 0,
    bonding_curve_raised_amount     uint256 DEFAULT 0,
    bonding_curve_goal_amount       uint256 DEFAULT 0,
    bonding_curve_current_amount_usd usd_amount DEFAULT 0,
    bonding_curve_goal_amount_usd   usd_amount DEFAULT 0,
    bonding_curve_migrated          BOOLEAN DEFAULT FALSE,
    lookup                          TEXT NOT NULL DEFAULT '', -- contract_address + ticker + creator lookup
    log_index                       BIGINT,
    title                           TEXT,
    description                     TEXT,
    image_url                       TEXT,
    bnb_bsc_metadata_owner_address  TEXT,
    PRIMARY KEY (contract_address)
);

CREATE INDEX IF NOT EXISTS idx_tokens_creator ON tokens (content_author_id);
CREATE INDEX IF NOT EXISTS idx_tokens_created_at ON tokens (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tokens_lookup_gist ON tokens USING gist (lookup gist_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_tokens_platform ON tokens (platform);
CREATE INDEX IF NOT EXISTS idx_tokens_type ON tokens ("type");
CREATE INDEX IF NOT EXISTS idx_tokens_contract_address_lower ON tokens (LOWER(contract_address));
CREATE INDEX IF NOT EXISTS idx_tokens_external_with_base ON tokens (external_address, base_token);

CREATE OR REPLACE FUNCTION update_tokens_lookup_on_user_change()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE tokens
    SET lookup = LOWER(TRIM(
        COALESCE(contract_address, '') || ' ' ||
        COALESCE(ticker, '') || ' ' ||
        COALESCE(NEW.username, '') || ' ' ||
        COALESCE(NEW.display_name, '')
    ))
    WHERE LOWER(content_author_id) = LOWER(NEW.content_author_id);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_update_tokens_lookup_on_user_change
    AFTER UPDATE OF username, display_name
    ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_tokens_lookup_on_user_change();

CREATE TABLE IF NOT EXISTS uniswap_pools (
                                             pool_address TEXT NOT NULL,
                                             token_address TEXT NOT NULL,
                                             token0 TEXT NOT NULL,
                                             token1 TEXT NOT NULL,
                                             fee BIGINT NOT NULL,
                                             created_at TIMESTAMP NOT NULL,
                                             PRIMARY KEY (pool_address),
                                             FOREIGN KEY (token_address) REFERENCES tokens(contract_address) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_uniswap_pools_token0 ON uniswap_pools (token0);
CREATE INDEX IF NOT EXISTS idx_uniswap_pools_token1 ON uniswap_pools (token1);

CREATE TABLE IF NOT EXISTS token_swaps (
    created_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    transaction_hash        TEXT NOT NULL,
    contract_address        TEXT NOT NULL,
    external_address        TEXT NOT NULL,
    user_blockchain_address TEXT NOT NULL,
    direction               BOOLEAN NOT NULL, -- false = buy, true = sell
    input_amount            uint256 NOT NULL, -- base token amount (buy) or token amount (sell)
    output_amount           uint256 NOT NULL, -- token amount (buy) or base token amount (sell)
    fee                     uint256 NOT NULL DEFAULT 0,
    price_usd               usd_amount NOT NULL,
    log_index               BIGINT,
    PRIMARY KEY (transaction_hash, contract_address, user_blockchain_address)
);

CREATE INDEX IF NOT EXISTS idx_token_swaps_contract ON token_swaps (contract_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_token_swaps_ion_connect ON token_swaps (external_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_token_swaps_user_blockchain_address ON token_swaps (user_blockchain_address);
CREATE INDEX IF NOT EXISTS idx_token_swaps_created_at ON token_swaps (created_at DESC);

CREATE TABLE IF NOT EXISTS user_token_positions (
    updated_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    user_blockchain_address TEXT NOT NULL,
    contract_address        TEXT NOT NULL,
    external_address        TEXT NOT NULL,
    user_external_address   TEXT,
    amount                  uint256 NOT NULL DEFAULT 0,
    avg_buy_price_usd       usd_amount DEFAULT 0,
    total_invested_usd      usd_amount DEFAULT 0,
    PRIMARY KEY (user_blockchain_address, contract_address)
);

CREATE INDEX IF NOT EXISTS idx_user_token_positions_user ON user_token_positions (user_blockchain_address);
CREATE INDEX IF NOT EXISTS idx_user_token_positions_contract ON user_token_positions (contract_address);
CREATE INDEX IF NOT EXISTS idx_user_token_positions_ion_connect ON user_token_positions (external_address);

CREATE TABLE IF NOT EXISTS tokens_featured (
    created_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    external_address     TEXT NOT NULL,
    PRIMARY KEY (external_address),
    FOREIGN KEY (external_address) REFERENCES tokens(external_address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tokens_featured_created_at ON tokens_featured (created_at DESC);

CREATE OR REPLACE FUNCTION update_token_holders_count_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;
        END IF;
        PERFORM update_token_platform_holders_count(NEW.external_address, NEW.user_external_address, 0, NEW.amount);
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.amount > 0 AND NEW.amount = 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;
        ELSIF OLD.amount = 0 AND NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;
        END IF;
        PERFORM update_token_platform_holders_count(NEW.external_address, NEW.user_external_address, OLD.amount, NEW.amount);
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.amount > 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE contract_address = OLD.contract_address;
        END IF;
        PERFORM update_token_platform_holders_count(OLD.external_address, OLD.user_external_address, OLD.amount, 0);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER user_token_position_changed
AFTER INSERT OR UPDATE OR DELETE ON user_token_positions
FOR EACH ROW
EXECUTE FUNCTION update_token_holders_count_trigger();

CREATE TABLE IF NOT EXISTS global_settings (
    value TEXT NOT NULL,
    key TEXT PRIMARY KEY
) WITH (FILLFACTOR = 70);

CREATE OR REPLACE FUNCTION create_transactions_mod_index()
RETURNS void AS $$
DECLARE
    workers_count INT;
    index_exists BOOLEAN;
    i INT;
BEGIN
    SELECT value::INT INTO workers_count FROM global_settings WHERE key = 'workers';

    IF workers_count IS NULL THEN
        RETURN;
    END IF;

    FOR i IN 0..(workers_count - 1) LOOP
        SELECT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'transactions'
            AND indexname = format('idx_transactions_worker_%s', i)
        ) INTO index_exists;

        IF NOT index_exists THEN
            EXECUTE format(
                'CREATE INDEX idx_transactions_worker_%s
                 ON transactions (block_number, transaction_index)
                 INCLUDE (transaction_hash, from_address, to_address, block_timestamp, chain_id, value, input)
                 WHERE MOD(i, %s) = %s',
                i, workers_count, i
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE MATERIALIZED VIEW IF NOT EXISTS token_volumes_24h AS
SELECT
    ts.contract_address,
    t.external_address,
    t."type" as token_type,
    COALESCE(SUM(
        CASE
            WHEN ts.direction = true THEN ts.input_amount::numeric * ts.price_usd
            ELSE ts.output_amount::numeric * ts.price_usd
        END
    ), 0) as volume_24h,
    MAX(ts.created_at) as last_updated
FROM token_swaps ts
JOIN tokens t ON t.contract_address = ts.contract_address
WHERE ts.created_at >= NOW() - INTERVAL '24 hours'
GROUP BY ts.contract_address, t.external_address, t."type";

CREATE UNIQUE INDEX IF NOT EXISTS idx_token_volumes_24h_contract ON token_volumes_24h (contract_address);
CREATE INDEX IF NOT EXISTS idx_token_volumes_24h_volume ON token_volumes_24h (volume_24h DESC);
CREATE INDEX IF NOT EXISTS idx_token_volumes_24h_external ON token_volumes_24h (external_address);

CREATE OR REPLACE FUNCTION refresh_token_volumes_24h()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW token_volumes_24h;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS base_token_prices (
    token_address       TEXT NOT NULL,
    token_symbol        TEXT NOT NULL,
    price_usd           usd_amount NOT NULL,
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (token_address)
);
CREATE INDEX IF NOT EXISTS idx_base_token_prices_symbol ON base_token_prices (token_symbol);

CREATE TABLE IF NOT EXISTS base_token_price_history (
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    token_address       TEXT NOT NULL,
    price_usd           usd_amount NOT NULL,
    PRIMARY KEY (token_address, created_at),
    FOREIGN KEY (token_address) REFERENCES base_token_prices(token_address) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION decode_base_token_from_input(tx_input TEXT) -- Decode baseToken parameter from swap() transaction input
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    base_token_offset_bytes INT;
    base_token_length_bytes INT;
    base_token_hex TEXT;
    data_start_pos INT;
BEGIN
    hex_clean := REPLACE(tx_input, '0x', '');
    hex_clean := substring(hex_clean from 9); -- Skip first 8 hex chars (4 bytes = function signature)

    -- baseToken is parameter index 0 (offset to bytes data)
    base_token_offset_bytes := decode_uint256('0x' || hex_clean, 0)::INT;

    IF base_token_offset_bytes = 0 THEN
        RETURN NULL;
    END IF;

    base_token_length_bytes := decode_uint256('0x' || hex_clean, base_token_offset_bytes / 32)::INT;

    IF base_token_length_bytes = 0 OR base_token_length_bytes > 32 THEN
        RETURN NULL;
    END IF;

    data_start_pos := (base_token_offset_bytes + 32) * 2 + 1;
    base_token_hex := substring(hex_clean from data_start_pos for (base_token_length_bytes * 2));

    RETURN LOWER('0x' || base_token_hex);
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION decode_to_token_from_input(tx_input TEXT)
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    to_token_offset_bytes INT;
    to_token_length_bytes INT;
    ext_length INT;
    to_token_hex TEXT;
    data_start_pos INT;
    external_address TEXT;
    result TEXT;
BEGIN
    hex_clean := REPLACE(tx_input, '0x', '');
    hex_clean := substring(hex_clean from 9); -- Skip first 8 hex chars (4 bytes = function signature)

    -- toToken is parameter index 1 (second parameter, after baseToken at index 0)
    to_token_offset_bytes := decode_uint256('0x' || hex_clean, 1)::INT;

    IF to_token_offset_bytes = 0 THEN
        RETURN '';
    END IF;

    to_token_length_bytes := decode_uint256('0x' || hex_clean, to_token_offset_bytes / 32)::INT;
    IF to_token_length_bytes = 0 THEN
        RETURN '';
    END IF;

    -- Extract toToken hex data (starts 32 bytes after the length word)
    data_start_pos := (to_token_offset_bytes + 32) * 2 + 1;
    to_token_hex := substring(hex_clean from data_start_pos for (to_token_length_bytes * 2));
    -- first 20 bytes is content creator token, for content tokens
    external_address := to_token_hex;
    ext_length := char_length(external_address);
    if ext_length <= 40 THEN
        -- For 1+ swaps: toToken is just 20-byte contract address, no external_address
        -- Return empty string so trigger will use pair_id lookup
        RETURN '';
    END IF;
    external_address := substring(external_address from 41);
    result := rtrim(convert_from(decode(external_address, 'hex'), 'UTF8'), E'\\0');

    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        RETURN '';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION decode_uint256(hex_data TEXT, offset_words INT) -- function to decode uint256 from hex string
RETURNS NUMERIC AS $$
DECLARE
    hex_value TEXT;
    result NUMERIC := 0;
    i INT;
    digit INT;
    hex_position INT;
BEGIN
    hex_data := REPLACE(hex_data, '0x', '');
    hex_position := (offset_words * 64) + 1;
    hex_value := substring(hex_data from hex_position for 64);
    hex_value := lpad(hex_value, 64, '0');
    FOR i IN 1..length(hex_value) LOOP
        digit := CASE substring(hex_value from i for 1)
            WHEN '0' THEN 0 WHEN '1' THEN 1 WHEN '2' THEN 2 WHEN '3' THEN 3
            WHEN '4' THEN 4 WHEN '5' THEN 5 WHEN '6' THEN 6 WHEN '7' THEN 7
            WHEN '8' THEN 8 WHEN '9' THEN 9 WHEN 'a' THEN 10 WHEN 'b' THEN 11
            WHEN 'c' THEN 12 WHEN 'd' THEN 13 WHEN 'e' THEN 14 WHEN 'f' THEN 15
            WHEN 'A' THEN 10 WHEN 'B' THEN 11 WHEN 'C' THEN 12 WHEN 'D' THEN 13
            WHEN 'E' THEN 14 WHEN 'F' THEN 15
            ELSE 0
        END;
        result := result * 16 + digit;
    END LOOP;

    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        RAISE WARNING 'decode_uint256 failed for hex_data_len=%, offset_words=%, error=%', length(hex_data), offset_words, SQLERRM;
        RETURN 0;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION decode_string_abi(hex_data TEXT, param_index INT) -- Decoding string from ABI-encoded data
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    string_offset_bytes INT;
    string_offset_words INT;
    string_length INT;
    string_hex TEXT;
    hex_position INT;
    result TEXT;
BEGIN
    hex_clean := REPLACE(hex_data, '0x', '');
    string_offset_bytes := decode_uint256('0x' || hex_clean, param_index)::INT;
    string_offset_words := string_offset_bytes / 32;
    string_length := decode_uint256('0x' || hex_clean, string_offset_words)::INT;

    hex_position := (string_offset_words + 1) * 64 + 1;
    string_hex := substring(hex_clean from hex_position for (string_length * 2));

    IF length(string_hex) > 0 AND string_length > 0 THEN
        string_hex := substring(string_hex from 1 for (string_length * 2));
        result := convert_from(decode(string_hex, 'hex'), 'UTF8');
    ELSE
        result := '';
    END IF;

    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        RAISE WARNING 'decode_string_abi failed: hex_data_len=%, param_index=%, error=%', length(hex_clean), param_index, SQLERRM;
        RETURN '';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION process_bonded_token_created(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT
) RETURNS VOID AS $$
DECLARE
    v_token_address TEXT;
    v_external_address TEXT;
    v_external_address_raw TEXT;
    v_platform platform_type;
    v_platform_prefix TEXT;
    v_total_supply NUMERIC;
    v_token_type TEXT;
    v_username TEXT;
    v_display_name TEXT;
    v_lookup_value TEXT;
    v_kind INT;
    v_parts TEXT[];
    v_token_symbol TEXT;
BEGIN
    IF array_length(p_topics, 1) < 2 THEN
        RETURN;
    END IF;

    v_token_address := LOWER('0x' || substring(p_topics[2] from 27 for 40)); -- topics[1] = token address (indexed)

    v_token_symbol := decode_string_abi(p_data, 1);
    v_external_address_raw := decode_string_abi(p_data, 2);
    v_total_supply := decode_uint256(p_data, 3);

    IF v_external_address_raw IS NULL OR v_external_address_raw = '' THEN
        RAISE WARNING 'Empty external address, skipping token creation';
        RETURN;
    END IF;

    -- Parse platform and type from prefix (a, b, c, d for IonConnect; z, y, x, w for X.com)
    v_platform_prefix := substring(v_external_address_raw, 1, 1);
    v_platform := get_platform_group(v_external_address_raw);

    IF v_platform IS NULL THEN
        RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address_raw;
        RETURN;
    END IF;

    v_external_address := substring(v_external_address_raw from 2);

    CASE
        WHEN v_platform_prefix IN ('a', 'z') THEN
            v_token_type := 'profile';
        WHEN v_platform_prefix IN ('b', 'y') THEN
            v_token_type := 'post';
        WHEN v_platform_prefix IN ('c', 'x') THEN
            v_token_type := 'video';
        WHEN v_platform_prefix IN ('d', 'w') THEN
            v_token_type := 'article';
        ELSE
            RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address_raw;
            RETURN;
    END CASE;

    -- For ALL tokens, content_author_id will be populated from first Swapped event
    IF v_token_type IS NULL THEN
        RAISE WARNING 'Failed to determine token type for %, skipping token creation', v_external_address;
        RETURN;
    END IF;

    INSERT INTO tokens (
        created_at, updated_at, contract_address, external_address, platform,
        ticker, total_supply, content_author_id, type, log_index
    )
    VALUES (
        p_block_timestamp,
        p_block_timestamp,
        v_token_address,
        v_external_address,
        v_platform,
        CASE
            WHEN v_platform = 'ionconnect' AND v_token_type IN ('post', 'video', 'article')
            THEN v_external_address
            ELSE v_token_symbol
        END,
        v_total_supply,
        NULL, -- Will be filled on first swap
        v_token_type,
        p_log_index
    )
    ON CONFLICT (external_address) DO UPDATE SET
        updated_at = EXCLUDED.updated_at,
        total_supply = EXCLUDED.total_supply,
        contract_address = EXCLUDED.contract_address,
        platform = EXCLUDED.platform,
        ticker = COALESCE(EXCLUDED.ticker, tokens.ticker),
        log_index = COALESCE(EXCLUDED.log_index, tokens.log_index);

    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_pair_registered(
    p_topics TEXT[],
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_base_token TEXT;
    v_pair_id TEXT;
    v_other_token TEXT;
BEGIN
    IF array_length(p_topics, 1) < 4 THEN
        RETURN;
    END IF;

    v_pair_id := LOWER(p_topics[2]);
    v_base_token := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_other_token := LOWER('0x' || substring(p_topics[4] from 27 for 40));

    UPDATE tokens
    SET base_token = v_base_token, pair_id = v_pair_id, updated_at = p_block_timestamp
    WHERE LOWER(contract_address) = v_other_token;

    RAISE DEBUG 'PairRegistered processed: token=%, baseToken=%', v_other_token, v_base_token;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_swapped(
    p_transaction_hash TEXT,
    p_topics TEXT[],
    p_data TEXT,
    p_tx_input TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT,
    p_address TEXT
) RETURNS VOID AS $$
DECLARE
    v_swapper TEXT;
    v_pair_id TEXT;
    v_user_address TEXT;
    v_direction BOOLEAN;
    v_input_amount NUMERIC;
    v_output_amount NUMERIC;
    v_fee NUMERIC;
    v_price_usd usd_amount;
    v_ion_price_usd usd_amount;
    v_token_external_address TEXT;
    v_base_token TEXT;
    v_other_token TEXT;
    v_token_address TEXT;
    v_total_supply NUMERIC;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_pair_id := LOWER(p_topics[3]);
    v_direction := (decode_uint256(p_data, 0) != 0);
    v_input_amount := decode_uint256(p_data, 1);
    v_output_amount := decode_uint256(p_data, 2);
    v_fee := decode_uint256(p_data, 3);

    BEGIN
        v_token_external_address := decode_to_token_from_input(p_tx_input);
        v_base_token := decode_base_token_from_input(p_tx_input);
    EXCEPTION WHEN OTHERS THEN
        v_token_external_address := NULL;
        v_base_token := NULL;
    END;

    IF v_token_external_address IS NOT NULL AND length(v_token_external_address) > 0 THEN
        v_token_external_address := substring(v_token_external_address from 2);

        SELECT
            t.contract_address,
            t.base_token,
            bp.price_usd,
            t.external_address,
            t.total_supply
        INTO v_token_address, v_other_token, v_ion_price_usd, v_token_external_address, v_total_supply
        FROM tokens t
        CROSS JOIN base_token_prices bp
        WHERE (t.external_address = v_token_external_address)
            AND bp.token_symbol = 'ION';
        IF v_token_address IS NULL THEN
            RAISE WARNING 'Token with external_address % not found, skipping swap', v_token_external_address;
            RETURN;
        END IF;
    ELSE
        SELECT
            t.contract_address,
            t.base_token,
            bp.price_usd,
            t.external_address,
            t.total_supply
        INTO v_token_address, v_other_token, v_ion_price_usd, v_token_external_address, v_total_supply
        FROM tokens t
        CROSS JOIN base_token_prices bp
        WHERE (t.pair_id = v_pair_id)
          AND bp.token_symbol = 'ION';
        IF v_token_address IS NULL THEN
            RAISE WARNING 'Token with pair % not found, skipping swap', v_pair_id;
            RETURN;
        END IF;
    END IF;

    IF v_ion_price_usd IS NULL THEN
        RAISE WARNING 'ION price not found, skipping swap for tx %', p_transaction_hash;
        RETURN;
    END IF;

    v_user_address := v_swapper;

    IF v_input_amount = 0 OR v_output_amount = 0 THEN
        RAISE WARNING 'Invalid swap amounts (input=%, output=%) for tx %, skipping', v_input_amount, v_output_amount, p_transaction_hash;
        RETURN;
    END IF;

    IF v_direction = false THEN -- buy
        v_price_usd := (v_input_amount / v_output_amount) * v_ion_price_usd;
    ELSE -- sell
        v_price_usd := (v_output_amount / v_input_amount) * v_ion_price_usd;
    END IF;

    INSERT INTO token_swaps (
        created_at, transaction_hash, contract_address, external_address,
        user_blockchain_address, direction, input_amount, output_amount, fee, price_usd, log_index
    )
    VALUES (
        p_block_timestamp, p_transaction_hash, v_token_address, v_token_external_address,
        v_user_address, v_direction, v_input_amount, v_output_amount, v_fee, v_price_usd, p_log_index
    )
    ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING;

    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_ion_price_usd, v_total_supply);


    RAISE DEBUG 'Swapped processed: token=%, user=%', v_token_address, v_user_address;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_pool_registered(
    p_topics TEXT[],
    p_data     TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_token0 TEXT;
    v_pool_address TEXT;
    v_token1 TEXT;
    v_fee SMALLINT;
    v_token_address TEXT;
BEGIN
    IF array_length(p_topics, 1) < 4 THEN
        RETURN;
    END IF;

    v_token0 := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_token1 := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_fee := p_topics[4]::BIGINT;
    v_pool_address := LOWER('0x' || substring(p_data from (64+27))); -- 64 is hex abi offset (2nd) + 27 prefix to trim 20 bytes of addr

    IF v_pool_address IS NULL OR v_pool_address = '' THEN
        RAISE EXCEPTION 'Failed to decode pool address % %', v_token0, v_token1;
        RETURN;
    END IF;

    SELECT tokens.contract_address from tokens WHERE
        (LOWER(contract_address) = LOWER(v_token0) and base_token = v_token1) OR
        (LOWER(contract_address) = LOWER(v_token1) and base_token = v_token0) LIMIT 1 -- only one, creator token cannot be bought with content tokens
    INTO v_token_address;

    IF v_token_address IS NULL OR v_token_address = '' THEN
        RAISE WARNING 'Failed to get token for tokens pool % %', v_token0, v_token1;
        RETURN;
    END IF;

    INSERT INTO uniswap_pools(pool_address, token_address, token0, token1, fee, created_at)
    VALUES (v_pool_address,v_token_address, v_token0, v_token1, v_fee, p_block_timestamp) ON CONFLICT DO NOTHING;

    RAISE DEBUG 'PoolCreated processed: token=%, token0=% token1=% pool=%v fee=%v', v_token_address, v_token0, v_token1, v_pool_address, v_fee;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION process_swapped_uniswap(
    p_transaction_hash TEXT,
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT,
    p_address TEXT
) RETURNS VOID AS $$
DECLARE
    v_swapper TEXT;
    v_recipient TEXT;
    v_user_address TEXT;
    v_direction BOOLEAN;
    v_input_amount0 NUMERIC;
    v_input_amount1 NUMERIC;
    v_output_amount NUMERIC;
    v_input_amount NUMERIC;
    v_fee NUMERIC;
    v_price_usd usd_amount;
    v_ion_price_usd usd_amount;
    v_token_external_address TEXT;
    v_base_token TEXT;
    v_token0_is_tc_token BOOLEAN;
    v_token_address TEXT;
    v_total_supply NUMERIC;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_input_amount0 := to_int256(decode_uint256(p_data, 0));
    v_input_amount1 := to_int256(decode_uint256(p_data, 1));
    SELECT
        t.contract_address,
        t.base_token,
        t.external_address,
        bp.price_usd,
        p.token0 = t.contract_address,
        p.fee,
        t.total_supply
    INTO v_token_address, v_base_token,v_token_external_address, v_ion_price_usd, v_token0_is_tc_token, v_fee, v_total_supply
    FROM tokens t
             CROSS JOIN base_token_prices bp
             JOIN uniswap_pools p ON p.token0 = t.contract_address OR p.token1 = t.contract_address
    WHERE p.pool_address = p_address
      AND bp.token_symbol = 'ION'; -- TODO: handle other tokens.

    IF v_token_address IS NULL THEN
        RAISE WARNING 'Token with pool % not found, skipping swap', p_address;
        RETURN;
    END IF;

    IF v_ion_price_usd IS NULL THEN
        RAISE WARNING 'ION price not found, skipping swap for tx %', p_transaction_hash;
        RETURN;
    END IF;


    IF v_input_amount = 0 OR v_output_amount = 0 THEN
        RAISE WARNING 'Invalid swap amounts (input=%, output=%) for tx %, skipping', v_input_amount, v_output_amount, p_transaction_hash;
        RETURN;
    END IF;

    if (v_token0_is_tc_token = TRUE AND v_input_amount0 > 0) OR (v_token0_is_tc_token = FALSE AND v_input_amount1 > 0) THEN -- sell of tc token
        v_input_amount = v_input_amount0;
        v_output_amount = v_input_amount1; -- base
        v_direction = true;
    ELSE
        v_input_amount = v_input_amount1;
        v_output_amount = v_input_amount0;
        v_direction = false;
    END IF;
    v_input_amount = ABS(v_input_amount);
    v_output_amount = ABS(v_output_amount);
    IF v_direction = false THEN -- buy
        v_user_address := v_recipient;
        v_price_usd := (v_input_amount / v_output_amount) * v_ion_price_usd;
    ELSE -- sell
        v_user_address = v_swapper;
        v_price_usd := (v_output_amount / v_input_amount) * v_ion_price_usd;
    END IF;

    INSERT INTO token_swaps (
        created_at, transaction_hash, contract_address, external_address,
        user_blockchain_address, direction, input_amount, output_amount, fee, price_usd, log_index
    )
    VALUES (
               p_block_timestamp, p_transaction_hash, v_token_address, v_token_external_address,
               v_user_address, v_direction, v_input_amount, v_output_amount, v_fee, v_price_usd, p_log_index
           )
    ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING;

    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                            v_direction, v_input_amount, v_output_amount, v_price_usd, v_ion_price_usd, v_total_supply);

    RAISE DEBUG 'Uniswap swap processed: token=%, user=%', v_token_address, v_user_address;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_market_cap_and_position(
    p_block_timestamp TIMESTAMP,
    p_user_blockchain_address TEXT,
    p_token_address TEXT,
    p_token_external_address TEXT,
    p_direction BOOLEAN,
    p_input_amount NUMERIC,
    p_output_amount NUMERIC,
    p_price_usd NUMERIC,
    p_ion_price_usd NUMERIC,
    p_total_supply NUMERIC
) RETURNS VOID AS $$
    DECLARE
        v_user_external_address TEXT;
        v_market_cap_usd usd_amount;
        v_market_cap_ion NUMERIC;
        v_price_ion NUMERIC;
        v_cost_usd usd_amount;
        v_username TEXT;
        v_display_name TEXT;
        v_avatar TEXT;
        v_token_type TEXT;
        v_platform platform_type;
    BEGIN
    IF p_direction = false THEN
        v_price_ion := p_input_amount / p_output_amount;
    ELSE
        v_price_ion := p_output_amount / p_input_amount;
    END IF;

    v_market_cap_usd := p_price_usd * (p_total_supply / 1e18);
    v_market_cap_ion := v_price_ion * p_total_supply;

    SELECT external_address, username, display_name, avatar
    INTO v_user_external_address, v_username, v_display_name, v_avatar
    FROM users
    WHERE LOWER(content_author_id) = LOWER(p_user_blockchain_address);

    SELECT type, platform INTO v_token_type, v_platform FROM tokens WHERE contract_address = p_token_address;

    UPDATE tokens t
    SET price_usd = p_price_usd,
        market_cap_usd = v_market_cap_usd,
        market_cap = v_market_cap_ion,
        updated_at = p_block_timestamp,
        content_author_id = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
            THEN p_user_blockchain_address
            ELSE t.content_author_id
        END,
        ticker = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
                 AND v_platform = 'ionconnect' AND v_token_type = 'profile'
                 AND v_username IS NOT NULL
            THEN v_username
            ELSE t.ticker
        END,
        title = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
                 AND v_platform = 'ionconnect' AND v_display_name IS NOT NULL
            THEN v_display_name
            ELSE t.title
        END,
        image_url = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
                 AND v_avatar IS NOT NULL
            THEN v_avatar
            ELSE t.image_url
        END,
        lookup = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false AND v_username IS NOT NULL THEN
                LOWER(TRIM(
                    COALESCE(t.contract_address, '') || ' ' ||
                    COALESCE(t.ticker, '') || ' ' ||
                    COALESCE(v_username, '') || ' ' ||
                    COALESCE(v_display_name, '')
                ))
            ELSE t.lookup
        END
    WHERE contract_address = p_token_address;

    v_cost_usd := (p_input_amount / 1e18) * p_ion_price_usd;

    IF p_direction = false THEN -- buy
        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, avg_buy_price_usd, total_invested_usd, updated_at
        )
        VALUES (
                   p_user_blockchain_address, p_token_address, p_token_external_address,
                   v_user_external_address,
                   p_output_amount, p_price_usd, v_cost_usd, p_block_timestamp
               )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
                                                                    amount = user_token_positions.amount + EXCLUDED.amount,
                                                                    total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
                                                                    avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) /
                                                                                        NULLIF((user_token_positions.amount + EXCLUDED.amount)::NUMERIC, 0),
                                                                    updated_at = EXCLUDED.updated_at,
                                                                    user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address); -- Update only if new value is not NULL
    ELSE -- sell
        UPDATE user_token_positions
        SET amount = GREATEST(amount - p_input_amount, 0),
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
    END; $$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION process_tx_log_event()
RETURNS TRIGGER AS $$
DECLARE
    v_block_timestamp TIMESTAMP;
    v_tx_input TEXT;
BEGIN
    SELECT block_timestamp, input INTO v_block_timestamp, v_tx_input
    FROM transactions
    WHERE transaction_hash = NEW.transaction_hash;

    CASE NEW.topic0
        WHEN '0x7a69aeb15d1aa44b3fec40fc8767221a5e4d2f41e58421d34db80a63f5a619c7' THEN -- BondedTokenCreated
            PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_block_timestamp, NEW.log_index);
        WHEN '0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4' THEN -- PairRegistered
            PERFORM process_pair_registered(NEW.topics, v_block_timestamp);
        WHEN '0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0' THEN -- Swapped
            PERFORM process_swapped(NEW.transaction_hash, NEW.topics, NEW.data, v_tx_input, v_block_timestamp, NEW.log_index, NEW.address);
        WHEN '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118' THEN -- PoolCreated (uniswap)
            PERFORM process_pool_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67' THEN -- Swap (uniswap)
            PERFORM process_swapped_uniswap(NEW.transaction_hash, NEW.topics, NEW.data, v_block_timestamp, NEW.log_index, NEW.address);
        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER tx_log_event_trigger
    AFTER INSERT ON tx_logs
    FOR EACH ROW
EXECUTE FUNCTION process_tx_log_event();

CREATE TABLE IF NOT EXISTS token_platform_holders (
    external_address TEXT NOT NULL,
    platform_group platform_type NOT NULL,
    holders_count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (external_address, platform_group),
    FOREIGN KEY (external_address) REFERENCES tokens(external_address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_token_platform_holders_external ON token_platform_holders (external_address);

CREATE OR REPLACE FUNCTION get_platform_group(p_external_address TEXT)
RETURNS platform_type AS $$
BEGIN
    IF LEFT(p_external_address, 1) IN ('z','y','x','w') THEN
        RETURN 'xcom'::platform_type;
    ELSIF LEFT(p_external_address, 1) IN ('a','b','c','d') THEN
        RETURN 'ionconnect'::platform_type;
    ELSE
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION update_token_platform_holders_count(
    p_token_external_address TEXT,
    p_user_external_address TEXT,
    p_old_amount NUMERIC,
    p_new_amount NUMERIC
)
RETURNS VOID AS $$
DECLARE
    v_platform_group platform_type;
BEGIN
    IF p_user_external_address IS NULL OR p_user_external_address = '' THEN
        RETURN;
    END IF;

    SELECT platform_group INTO v_platform_group
    FROM users
    WHERE external_address = p_user_external_address;

    IF v_platform_group IS NULL THEN
        RETURN;
    END IF;

    IF p_old_amount = 0 AND p_new_amount > 0 THEN
        INSERT INTO token_platform_holders (external_address, platform_group, holders_count, updated_at)
        VALUES (p_token_external_address, v_platform_group, 1, NOW())
        ON CONFLICT (external_address, platform_group) DO UPDATE
        SET holders_count = token_platform_holders.holders_count + 1,
            updated_at = NOW();

    ELSIF p_old_amount > 0 AND p_new_amount = 0 THEN
        UPDATE token_platform_holders
        SET holders_count = GREATEST(holders_count - 1, 0),
            updated_at = NOW()
        WHERE external_address = p_token_external_address
          AND platform_group = v_platform_group;
    END IF;
END;
$$ LANGUAGE plpgsql;
