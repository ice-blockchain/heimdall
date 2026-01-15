-- SPDX-License-Identifier: ice License 1.0

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
            COALESCE(transaction_data->>'to', '0x0000000000000000000000000000000000000000'),
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

