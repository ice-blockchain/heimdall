-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE transactions ADD COLUMN IF NOT EXISTS dummy BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_transactions_dummy ON transactions (dummy);
CREATE INDEX IF NOT EXISTS idx_transactions_block_tx_idx ON transactions (block_number, transaction_index);

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
    -- Check if stream_id indicates dummy swap on real token
    IF NEW.stream_id = 'a69a079e-d500-42ee-af6d-22d5eb5b10df' 
       OR NEW.stream_id LIKE 'dummy-swaps-real-tokens-%' THEN
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

