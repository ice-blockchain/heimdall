-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    CREATE DOMAIN usd_amount AS NUMERIC(48, 18);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE DOMAIN uint256 AS NUMERIC(78, 0);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS users
(
    created_at           TIMESTAMP NOT NULL,
    updated_at           TIMESTAMP NOT NULL,
    id                   TEXT NOT NULL,
    master_pubkey        TEXT NOT NULL,
    blockchain_address   TEXT NOT NULL,
    ion_connect_address  TEXT,
    username             TEXT NOT NULL,
    display_name         TEXT,
    avatar               TEXT,
    lookup               TEXT NOT NULL DEFAULT '',
    ion_connect_relays   TEXT[],
    verified             BOOLEAN NOT NULL DEFAULT false,
    primary key(master_pubkey)
);

CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at);
CREATE INDEX IF NOT EXISTS idx_users_blockchain_address ON users (blockchain_address);
CREATE INDEX IF NOT EXISTS idx_users_master_pubkey ON users (master_pubkey);
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_users_lookup_gist ON users USING gist (lookup gist_trgm_ops);

CREATE TABLE IF NOT EXISTS transactions
(
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
    i                   BIGINT generated always as identity NOT NULL,
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
CREATE UNIQUE INDEX IF NOT EXISTS tx_logs_i_ix ON tx_logs (i);

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
    created_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    contract_address        TEXT NOT NULL, -- token contract address (ERC20)
    ion_connect_address     TEXT NOT NULL UNIQUE, -- nostr 'a' tag for this token (e.g. "30023:article_master_pubkey:d_tag")
    ticker                  TEXT NOT NULL,
    total_supply            uint256 NOT NULL,
    creator_master_pubkey   TEXT,
    type                    TEXT NOT NULL, -- profile/post/video/article
    base_token              TEXT,
    market_cap_usd          usd_amount DEFAULT 0,
    price_usd               usd_amount DEFAULT 0,
    holders_count           BIGINT DEFAULT 0,
    tx_log_id               BIGINT,
    PRIMARY KEY (contract_address),
    FOREIGN KEY (creator_master_pubkey) REFERENCES users(master_pubkey) ON DELETE CASCADE,
    FOREIGN KEY (tx_log_id) REFERENCES tx_logs(i) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_creator ON tokens (creator_master_pubkey);
CREATE INDEX IF NOT EXISTS idx_tokens_created_at ON tokens (created_at DESC);

CREATE TABLE IF NOT EXISTS token_swaps (
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    transaction_hash    TEXT NOT NULL,
    contract_address    TEXT NOT NULL,
    ion_connect_address TEXT NOT NULL,
    user_address        TEXT NOT NULL,
    direction           BOOLEAN NOT NULL, -- true = buy, false = sell
    input_amount        uint256 NOT NULL, -- base token amount (buy) or token amount (sell)
    output_amount       uint256 NOT NULL, -- token amount (buy) or base token amount (sell)
    fee                 uint256 NOT NULL DEFAULT 0,
    price_usd           usd_amount NOT NULL,
    tx_log_id           BIGINT,
    PRIMARY KEY (transaction_hash, contract_address, user_address),
    FOREIGN KEY (contract_address) REFERENCES tokens(contract_address) ON DELETE CASCADE,
    FOREIGN KEY (tx_log_id) REFERENCES tx_logs(i) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_token_swaps_contract ON token_swaps (contract_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_token_swaps_ion_connect ON token_swaps (ion_connect_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_token_swaps_user_address ON token_swaps (user_address);

CREATE TABLE IF NOT EXISTS user_token_positions (
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    master_pubkey       TEXT NOT NULL,
    contract_address    TEXT NOT NULL,
    ion_connect_address TEXT NOT NULL,
    amount              uint256 NOT NULL DEFAULT 0,
    avg_buy_price_usd   usd_amount DEFAULT 0,
    total_invested_usd  usd_amount DEFAULT 0,
    PRIMARY KEY (master_pubkey, contract_address),
    FOREIGN KEY (master_pubkey) REFERENCES users(master_pubkey) ON DELETE CASCADE,
    FOREIGN KEY (contract_address) REFERENCES tokens(contract_address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_token_positions_user ON user_token_positions (master_pubkey);
CREATE INDEX IF NOT EXISTS idx_user_token_positions_contract ON user_token_positions (contract_address);
CREATE INDEX IF NOT EXISTS idx_user_token_positions_ion_connect ON user_token_positions (ion_connect_address);

CREATE TABLE IF NOT EXISTS tokens_featured (
    created_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    ion_connect_address     TEXT NOT NULL,
    PRIMARY KEY (ion_connect_address),
    FOREIGN KEY (ion_connect_address) REFERENCES tokens(ion_connect_address) ON DELETE CASCADE
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
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.amount > 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE contract_address = OLD.contract_address;
        END IF;
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
    existing_index_def TEXT;
    expected_index_def TEXT;
BEGIN
    SELECT value::INT INTO workers_count FROM global_settings WHERE key = 'workers';

    IF workers_count IS NULL THEN
        RETURN;
    END IF;

    SELECT pg_get_indexdef(indexrelid) INTO existing_index_def
    FROM pg_stat_user_indexes
    WHERE indexrelname = 'idx_transactions_mod_tx_idx';

    expected_index_def := format('CREATE INDEX idx_transactions_mod_tx_idx ON public.transactions USING btree (mod(transaction_index, %s), block_number, transaction_index)', workers_count);

    IF existing_index_def IS NULL OR existing_index_def != expected_index_def THEN
        DROP INDEX IF EXISTS idx_transactions_mod_tx_idx;
        EXECUTE format('CREATE INDEX idx_transactions_mod_tx_idx ON transactions (MOD(transaction_index, %s), block_number, transaction_index ASC)', workers_count);
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE MATERIALIZED VIEW IF NOT EXISTS token_volumes_24h AS
SELECT
    contract_address,
    COALESCE(SUM(
        CASE
            WHEN direction = true THEN input_amount::numeric * price_usd
            ELSE output_amount::numeric * price_usd
        END
    ), 0) as volume_24h,
    MAX(created_at) as last_updated
FROM token_swaps
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY contract_address;

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
    to_token_hex TEXT;
    data_start_pos INT;
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
    
    result := rtrim(convert_from(decode(to_token_hex, 'hex'), 'UTF8'), E'\\0');
    
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
    p_tx_log_id BIGINT
) RETURNS VOID AS $$
DECLARE
    v_token_address TEXT;
    v_ion_connect_address TEXT;
    v_total_supply NUMERIC;
    v_creator_master_pubkey TEXT;
    v_token_type TEXT;
    v_username TEXT;
    v_kind INT;
    v_parts TEXT[];
BEGIN
    IF array_length(p_topics, 1) < 2 THEN
        RETURN;
    END IF;

    v_token_address := LOWER('0x' || substring(p_topics[2] from 27 for 40)); -- topics[1] = token address (indexed)
    
    v_ion_connect_address := decode_string_abi(p_data, 2); -- Parse ABI-encoded data: (name, symbol, ionConnectAddress, totalSupply)
    v_total_supply := decode_uint256(p_data, 3);
    
    IF v_ion_connect_address IS NULL OR v_ion_connect_address = '' OR NOT (v_ion_connect_address ~ '^[0-9]+:.+:') THEN
        RAISE WARNING 'Invalid ion_connect_address format: %, skipping token creation', v_ion_connect_address;
        RETURN;
    END IF;
    
    v_parts := string_to_array(v_ion_connect_address, ':');
    IF array_length(v_parts, 1) >= 2 THEN
        v_kind := v_parts[1]::INT;
        v_creator_master_pubkey := v_parts[2];
        
        CASE v_kind
            WHEN 0 THEN v_token_type := 'profile';
            WHEN 1 THEN v_token_type := 'post';
            WHEN 30023 THEN v_token_type := 'article';
            WHEN 30175 THEN v_token_type := 'post';
            ELSE
                RAISE WARNING 'Invalid nostr kind % in ion_connect_address %, skipping token creation', v_kind, v_ion_connect_address;
                RETURN;
        END CASE;
    END IF;
    
    IF v_token_type IS NULL THEN
        RAISE WARNING 'Failed to parse token type from ion_connect_address %, skipping token creation', v_ion_connect_address;
        RETURN;
    END IF;
    
    SELECT username INTO v_username
    FROM users
    WHERE master_pubkey = v_creator_master_pubkey;
    
    INSERT INTO tokens (
        created_at, updated_at, contract_address, ion_connect_address,
        ticker, total_supply, creator_master_pubkey, type, tx_log_id
    )
    VALUES (
        p_block_timestamp, p_block_timestamp, v_token_address, v_ion_connect_address,
        COALESCE(v_username, ''), v_total_supply, v_creator_master_pubkey, v_token_type, p_tx_log_id
    )
    ON CONFLICT (ion_connect_address) DO UPDATE SET
        updated_at = EXCLUDED.updated_at,
        total_supply = EXCLUDED.total_supply,
        creator_master_pubkey = EXCLUDED.creator_master_pubkey,
        contract_address = EXCLUDED.contract_address,
        ticker = COALESCE(EXCLUDED.ticker, tokens.ticker),
        tx_log_id = COALESCE(EXCLUDED.tx_log_id, tokens.tx_log_id);
    
    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_pair_registered(
    p_topics TEXT[],
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_base_token TEXT;
    v_other_token TEXT;
BEGIN
    IF array_length(p_topics, 1) < 4 THEN
        RETURN;
    END IF;
    
    v_base_token := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_other_token := LOWER('0x' || substring(p_topics[4] from 27 for 40));
    
    UPDATE tokens
    SET base_token = v_base_token, updated_at = p_block_timestamp
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
    p_tx_log_id BIGINT
) RETURNS VOID AS $$
DECLARE
    v_swapper TEXT;
    v_user_address TEXT;
    v_direction BOOLEAN;
    v_input_amount NUMERIC;
    v_output_amount NUMERIC;
    v_fee NUMERIC;
    v_price_usd usd_amount;
    v_ion_price_usd usd_amount;
    v_token_ion_connect TEXT;
    v_base_token TEXT;
    v_other_token TEXT;
    v_token_address TEXT;
    v_user_master_pubkey TEXT;
    v_delta_market_cap usd_amount;
    v_token_amount NUMERIC;
    v_sign NUMERIC;
    v_cost_usd usd_amount;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;
    
    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_direction := (decode_uint256(p_data, 0) != 0);
    v_input_amount := decode_uint256(p_data, 1);
    v_output_amount := decode_uint256(p_data, 2);
    v_fee := decode_uint256(p_data, 3);
    
    
    v_token_ion_connect := decode_to_token_from_input(p_tx_input); -- Extract toToken and baseToken from tx input
    v_base_token := decode_base_token_from_input(p_tx_input);
    
    IF v_token_ion_connect IS NULL OR v_token_ion_connect = '' THEN
        RAISE WARNING 'Failed to decode toToken from tx input for tx %', p_transaction_hash;
        RETURN;
    END IF;
    
    SELECT contract_address, base_token INTO v_token_address, v_other_token
    FROM tokens
    WHERE ion_connect_address = v_token_ion_connect;
    
    IF v_token_address IS NULL THEN
        RAISE WARNING 'Token with ion_connect_address % not found, skipping swap', v_token_ion_connect;
        RETURN;
    END IF;
    
    IF v_base_token IS NOT NULL AND v_other_token IS NOT NULL AND LOWER(v_base_token) != LOWER(v_other_token) THEN
        RAISE WARNING 'Base token mismatch: tx has %, token has %. Skipping swap for tx %', v_base_token, v_other_token, p_transaction_hash;
        RETURN;
    END IF;
    
    v_user_address := v_swapper;
    
    SELECT price_usd INTO v_ion_price_usd -- Get ION price
    FROM base_token_prices
    WHERE token_symbol = 'ION'
    LIMIT 1;

    IF v_ion_price_usd IS NULL THEN
        RAISE WARNING 'ION price not found, skipping swap for tx %', p_transaction_hash;
        RETURN;
    END IF;
    
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
        created_at, transaction_hash, contract_address, ion_connect_address,
        user_address, direction, input_amount, output_amount, fee, price_usd, tx_log_id
    )
    VALUES (
        p_block_timestamp, p_transaction_hash, v_token_address, v_token_ion_connect,
        v_user_address, v_direction, v_input_amount, v_output_amount, v_fee, v_price_usd, p_tx_log_id
    )
    ON CONFLICT (transaction_hash, contract_address, user_address) DO NOTHING;
    
    IF v_direction = false THEN
        v_token_amount := v_output_amount;
        v_sign := 1.0;
    ELSE
        v_token_amount := v_input_amount;
        v_sign := -1.0;
    END IF;
    
    v_delta_market_cap := v_sign * v_token_amount * v_price_usd;
    
    UPDATE tokens
    SET price_usd = v_price_usd,
        market_cap_usd = GREATEST(market_cap_usd + v_delta_market_cap, 0),
        updated_at = p_block_timestamp
    WHERE contract_address = v_token_address;
    
    SELECT master_pubkey INTO v_user_master_pubkey
    FROM users
    WHERE LOWER(blockchain_address) = LOWER(v_user_address);

    v_cost_usd := v_input_amount * v_ion_price_usd;
    
    IF v_direction = false THEN -- buy
        INSERT INTO user_token_positions (
            master_pubkey, contract_address, ion_connect_address,
            amount, avg_buy_price_usd, total_invested_usd, updated_at
        )
        VALUES (
            v_user_master_pubkey, v_token_address, v_token_ion_connect,
            v_output_amount, v_price_usd, v_cost_usd, p_block_timestamp
        )
        ON CONFLICT (master_pubkey, contract_address) DO UPDATE SET
            amount = user_token_positions.amount + EXCLUDED.amount,
            total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
            avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) / 
                                NULLIF((user_token_positions.amount + EXCLUDED.amount)::NUMERIC, 0),
            updated_at = EXCLUDED.updated_at;
    ELSE -- sell
        UPDATE user_token_positions
        SET amount = GREATEST(amount - v_input_amount, 0),
            updated_at = p_block_timestamp
        WHERE master_pubkey = v_user_master_pubkey
            AND contract_address = v_token_address;
    END IF;
    
    RAISE DEBUG 'Swapped processed: token=%, user=%', v_token_address, v_user_address;
END;
$$ LANGUAGE plpgsql;

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
        WHEN '0xcaa54a9b9817e12b67fd790dabf6f963cb9a083290c5c06c052ea18bb9b29427' THEN -- BondedTokenCreated
            PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_block_timestamp, NEW.i);
        WHEN '0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4' THEN -- PairRegistered
            PERFORM process_pair_registered(NEW.topics, v_block_timestamp);
        WHEN '0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0' THEN -- Swapped
            PERFORM process_swapped(NEW.transaction_hash, NEW.topics, NEW.data, v_tx_input, v_block_timestamp, NEW.i);
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
