-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users
(
    created_at           TIMESTAMP NOT NULL,
    updated_at           TIMESTAMP NOT NULL,
    id                   TEXT NOT NULL,
    master_pubkey        TEXT NOT NULL,
    username             TEXT NOT NULL,
    display_name         TEXT,
    avatar               TEXT,
    lookup               TEXT NOT NULL DEFAULT '',
    ion_connect_relays   TEXT[],
    verified             BOOLEAN NOT NULL DEFAULT false,
    primary key(master_pubkey)
);

CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at);
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
CREATE INDEX IF NOT EXISTS idx_transactions_mod_tx_idx ON transactions (MOD(transaction_index, %[1]v), block_number, transaction_index ASC);

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
