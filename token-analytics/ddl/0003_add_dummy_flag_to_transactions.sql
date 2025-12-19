-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE transactions ADD COLUMN IF NOT EXISTS dummy BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_transactions_block_tx_idx ON transactions (block_number, transaction_index);

CREATE OR REPLACE FUNCTION create_transactions_dummy_mod_indexes()
RETURNS void AS $$
DECLARE
    workers_count INT;
    index_exists BOOLEAN;
    old_index_exists BOOLEAN;
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
        ) INTO old_index_exists;

        IF old_index_exists THEN
            EXECUTE format('DROP INDEX IF EXISTS idx_transactions_worker_%s', i);
        END IF;
        SELECT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'transactions'
            AND indexname = format('idx_transactions_dummy_block_tx_worker_%s', i)
        ) INTO index_exists;

        IF NOT index_exists THEN
            EXECUTE format(
                'CREATE INDEX idx_transactions_dummy_block_tx_worker_%s
                 ON transactions (dummy, block_number, transaction_index)
                 WHERE MOD(i, %s) = %s',
                i, workers_count, i
            );
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

SELECT create_transactions_dummy_mod_indexes();

UPDATE transactions SET dummy = TRUE WHERE to_address LIKE '%0xdeadbeef%';

CREATE OR REPLACE FUNCTION set_dummy_flag_on_transaction()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if to_address contains 0xdeadbeef prefix (dummy tokens)
    IF NEW.to_address LIKE '0xdeadbeef%' THEN
        NEW.dummy := TRUE;
    ELSE
        NEW.dummy := FALSE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER set_dummy_flag_trigger
    BEFORE INSERT ON transactions
    FOR EACH ROW
EXECUTE FUNCTION set_dummy_flag_on_transaction();

CREATE OR REPLACE FUNCTION update_dummy_flag_from_stream()
RETURNS TRIGGER AS $$
BEGIN
   IF NEW.stream_id = '00000000-0000-0000-0000-000000000000' THEN
       UPDATE transactions 
       SET dummy = TRUE 
       WHERE transaction_hash = NEW.transaction_hash 
         AND dummy = FALSE;
   END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_dummy_flag_from_stream_trigger
    AFTER INSERT ON tx_logs
    FOR EACH ROW
EXECUTE FUNCTION update_dummy_flag_from_stream();


CREATE INDEX IF NOT EXISTS idx_transactions_to_address_dummy ON transactions (to_address, dummy) WHERE dummy = FALSE;