-- SPDX-License-Identifier: ice License 1.0
-- TODO: reorder fields properly
CREATE TABLE IF NOT EXISTS blocks (
                                      stream_id           TEXT NOT NULL,
                                      ingested_at         TIMESTAMP NOT NULL DEFAULT NOW(),
                                      block_number         BIGINT NOT NULL,
                                      block_hash          TEXT NOT NULL,
                                      timestamp           TIMESTAMP NOT NULL,
                                      base_fee_per_gas    BIGINT,
                                      blob_gas_used       BIGINT,
                                      difficulty          TEXT NOT NULL,
                                      excess_blob_gas     TEXT,
                                      extra_data          TEXT,
                                      gas_limit           BIGINT NOT NULL,
                                      gas_used            BIGINT NOT NULL,
                                      logs_bloom          TEXT,
                                      miner               TEXT NOT NULL,
                                      mix_hash            TEXT,
                                      nonce               TEXT,
                                      parent_beacon_block_root TEXT,
                                      parent_hash         TEXT NOT NULL,
                                      receipts_root       TEXT,
                                      requests_hash       TEXT,
                                      sha3_uncles         TEXT,
                                      size                TEXT,
                                      state_root          TEXT,
                                      transactions_root   TEXT,
                                      removed             BOOLEAN NOT NULL DEFAULT FALSE,
                                      PRIMARY KEY (block_number)
);

CREATE TABLE IF NOT EXISTS transactions
(
    chain_id              TEXT NOT NULL,
    block_number          BIGINT NOT NULL REFERENCES blocks(block_number) DEFERRABLE INITIALLY DEFERRED,
    transaction_hash      TEXT NOT NULL,
    transaction_index     BIGINT,
    gas                   BIGINT NOT NULL,
    gas_price            BIGINT NOT NULL,
    max_fee_per_gas      BIGINT,
    max_priority_fee_per_gas BIGINT,
    nonce                BIGINT NOT NULL,
    to_address           TEXT NOT NULL,
    transaction_type     TEXT,
    value                TEXT NOT NULL,
    y_parity             TEXT,
    input                TEXT,
    from_address         TEXT NOT NULL,
    PRIMARY KEY (transaction_hash)
);
CREATE INDEX IF NOT EXISTS idx_transactions_from_address ON transactions (from_address);

CREATE TABLE IF NOT EXISTS tx_logs
(
    i                   BIGINT generated always as identity NOT NULL,
    stream_id           TEXT NOT NULL,
    ingested_at         TIMESTAMP NOT NULL DEFAULT NOW(),
    address             TEXT NOT NULL,
    topic0              TEXT NOT NULL,
    topics              TEXT[],
    data                TEXT,
    block_number         BIGINT NOT NULL REFERENCES blocks(block_number) DEFERRABLE INITIALLY DEFERRED,
    transaction_hash     TEXT NOT NULL REFERENCES transactions(transaction_hash) DEFERRABLE INITIALLY DEFERRED,
    log_index            BIGINT NOT NULL,
    removed             BOOLEAN NOT NULL,
    processed_at        TIMESTAMP,
    primary key (transaction_hash, log_index)
);
CREATE UNIQUE INDEX IF NOT EXISTS tx_logs_i_ix ON tx_logs (i);
CREATE INDEX IF NOT EXISTS tx_logs_mod_i_ix ON tx_logs (MOD(i, %[1]v), block_number, log_index ASC);


CREATE TABLE IF NOT EXISTS incoming_data (
                               from_block_number BIGINT,
                               to_block_number BIGINT,
                               network TEXT,
                               stream_id TEXT,
                               data JSONB,
                               PRIMARY KEY (from_block_number,to_block_number,network)
);

CREATE INDEX IF NOT EXISTS incoming_data_to_block_number_idx ON incoming_data (to_block_number);

CREATE OR REPLACE FUNCTION trigger_move_incoming_logs()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO blocks (
        stream_id,
        block_number,
        block_hash,
        timestamp,
        base_fee_per_gas,
        blob_gas_used,
        difficulty,
        excess_blob_gas,
        extra_data,
        gas_limit,
        gas_used,
        logs_bloom,
        miner,
        mix_hash,
        nonce,
        parent_beacon_block_root,
        parent_hash,
        receipts_root,
        requests_hash,
        sha3_uncles,
        size,
        state_root,
        transactions_root,
        removed
    )
    VALUES (NEW.data ->> 'stream',
            (NEW.data -> 'block'->> 'number')::bigint,
            NEW.data -> 'block'->> 'hash',
            to_timestamp((NEW.data -> 'block'->> 'timestamp')::BIGINT),
            (NEW.data -> 'block'->> 'baseFeePerGas')::BIGINT,
            (NEW.data -> 'block'->> 'blobGasUsed')::BIGINT,
            NEW.data -> 'block'->> 'difficulty',
            NEW.data -> 'block'->> 'excessBlobGas',
            NEW.data -> 'block'->> 'extraData',
            (NEW.data -> 'block'->> 'gasLimit')::BIGINT,
            (NEW.data -> 'block'->> 'gasUsed')::BIGINT,
            NEW.data -> 'block'->> 'logsBloom',
            NEW.data -> 'block'->> 'miner',
            NEW.data -> 'block'->> 'mixHash',
            NEW.data -> 'block'->> 'nonce',
            NEW.data -> 'block'->> 'parentBeaconBlockRoot',
            NEW.data -> 'block'->> 'parentHash',
            NEW.data -> 'block'->> 'receiptsRoot',
            NEW.data -> 'block'->> 'requestsHash',
            NEW.data -> 'block'->> 'sha3Uncles',
            (NEW.data -> 'block'->> 'size')::BIGINT,
            NEW.data -> 'block'->> 'stateRoot',
            NEW.data -> 'block'->> 'transactionsRoot',
            false
    ) ON CONFLICT (block_number) DO NOTHING;


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
        to_address,
        transaction_type,
        value,
        y_parity,
        input,
        from_address
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
                 transaction_data->>'to',
                 transaction_data->>'type',
                 (transaction_data->>'value')::BIGINT,
                 (transaction_data->>'yParity')::BIGINT,
                 transaction_data->>'input',
                 transaction_data->>'from'
         FROM jsonb_array_elements(NEW.data -> 'block'->'transactions') as transaction_data
    ON CONFLICT(transaction_hash) DO NOTHING;

    INSERT INTO tx_logs(stream_id, address, topics, topic0, data, block_number, transaction_hash, log_index, removed)
    (SELECT
              NEW.data ->> 'stream',
              elem->>'address' as address,
              (SELECT t.topics from jsonb_to_record(elem) as t (topics TEXT[])) AS topics,
              (elem->'topics'->>0) as topics,
              elem->>'data' as data,
              (elem->>'blockNumber')::BIGINT as block_number,
              elem->>'transactionHash' as transaction_hash,
              (elem->>'logIndex')::BIGINT as log_index,
              (elem->>'removed')::BOOLEAN as removed
              FROM jsonb_array_elements(NEW.data -> 'logs') as elem)
    ON CONFLICT (transaction_hash, log_index) DO NOTHING;
    DELETE FROM incoming_data WHERE to_block_number<=(NEW.data -> 'block'->> 'number')::bigint;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_move_incoming_logs
    AFTER INSERT ON incoming_data
    FOR EACH ROW
EXECUTE FUNCTION trigger_move_incoming_logs();