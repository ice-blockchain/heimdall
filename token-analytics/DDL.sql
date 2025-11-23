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
    contract_address        TEXT NOT NULL UNIQUE,
    ion_connect_address     TEXT NOT NULL, -- nostr 'a' tag for this token (e.g. "30023:article_master_pubkey:d_tag")
    ticker                  TEXT NOT NULL,
    total_supply            uint256 NOT NULL,
    creator_master_pubkey   TEXT,
    type                    TEXT NOT NULL, -- profile/post/video/article
    base_token              TEXT,
    market_cap_usd          usd_amount DEFAULT 0,
    price_usd               usd_amount DEFAULT 0,
    holders_count           BIGINT DEFAULT 0,
    PRIMARY KEY (ion_connect_address),
    FOREIGN KEY (creator_master_pubkey) REFERENCES users(master_pubkey) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tokens_contract_address ON tokens (contract_address);
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
    price_usd           usd_amount NOT NULL,
    PRIMARY KEY (transaction_hash, contract_address, user_address),
    FOREIGN KEY (ion_connect_address) REFERENCES tokens(ion_connect_address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_token_swaps_contract_direction ON token_swaps (contract_address, direction, created_at DESC);
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
    FOREIGN KEY (ion_connect_address) REFERENCES tokens(ion_connect_address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_token_positions_user ON user_token_positions (master_pubkey);
CREATE INDEX IF NOT EXISTS idx_user_token_positions_token ON user_token_positions (contract_address);
CREATE INDEX IF NOT EXISTS idx_user_token_positions_ion_connect ON user_token_positions (ion_connect_address);

CREATE OR REPLACE FUNCTION update_token_holders_count_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE ion_connect_address = NEW.ion_connect_address;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.amount > 0 AND NEW.amount = 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE ion_connect_address = NEW.ion_connect_address;
        ELSIF OLD.amount = 0 AND NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE ion_connect_address = NEW.ion_connect_address;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.amount > 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE ion_connect_address = OLD.ion_connect_address;
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
    ion_connect_address,
    COALESCE(SUM(
        CASE
            WHEN direction = true THEN input_amount::numeric * price_usd
            ELSE output_amount::numeric * price_usd
        END
    ), 0) as volume_24h,
    MAX(created_at) as last_updated
FROM token_swaps
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY ion_connect_address;

CREATE OR REPLACE FUNCTION refresh_token_volumes_24h()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW token_volumes_24h;
END;
$$ LANGUAGE plpgsql;
