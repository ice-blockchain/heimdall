-- SPDX-License-Identifier: ice License 1.0

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
        WHEN '0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd' THEN -- BondingTokenCreated
        PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_block_timestamp, NEW.log_index);
        WHEN '0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c' THEN -- PairRegistered
        PERFORM process_pair_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81' THEN -- Swapped
        PERFORM process_swapped(NEW.transaction_hash, NEW.topics, NEW.data, v_tx_input, v_block_timestamp, NEW.log_index, NEW.address);
        WHEN '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118' THEN -- PoolCreated (uniswap)
        PERFORM process_pool_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67' THEN -- Swap (uniswap)
        PERFORM process_swapped_uniswap(NEW.transaction_hash, NEW.topics, NEW.data, v_block_timestamp, NEW.log_index, NEW.address);
        WHEN '0xbda77c1230f2354807b9e8307932c78ac43f6b38ea2e10d9886aa30c958300f5' THEN -- FeeTransfer
        PERFORM process_fee_transfer(NEW.topics, NEW.data, v_block_timestamp);
        ELSE
            NULL;
        END CASE;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS fees_transferred (
    updated_at             TIMESTAMP NOT NULL,
    token_external_address TEXT NOT NULL,
    recipient_bsc_address  TEXT NOT NULL,
    fee_type               TEXT NOT NULL,
    amount                 uint256 NOT NULL,
    PRIMARY KEY (token_external_address, recipient_bsc_address)
);

CREATE OR REPLACE FUNCTION process_fee_transfer(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_fee_amount NUMERIC;
    v_recipient TEXT;
    v_creator_bsc_address TEXT;
    v_affiliate_bsc_address TEXT;
    v_pair_id TEXT;
    v_external_address TEXT;
    v_fee_type TEXT;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;
    v_pair_id := LOWER(p_topics[2]);
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_fee_amount := decode_uint256(p_data, 0);
    SELECT
        t.content_author_id,
        t.affiliate_bsc_address,
        t.external_address
    INTO v_creator_bsc_address, v_affiliate_bsc_address, v_external_address
    FROM tokens t
    WHERE t.pair_id = v_pair_id;
    IF v_external_address IS NULL OR v_creator_bsc_address IS NULL THEN
        RAISE WARNING 'Token with pair % not found, skipping fee processing', v_pair_id;
        RETURN;
    END IF;
    IF LOWER(v_affiliate_bsc_address) = v_recipient THEN
        v_fee_type = 'affiliate';
    ELSIF LOWER(v_creator_bsc_address) = v_recipient THEN
        v_fee_type = 'creator';
    ELSIF v_recipient = '0x0000000000000000000000000000000000696f6e' THEN
        v_fee_type = 'burn';
    END IF;

    INSERT INTO fees_transferred (updated_at, token_external_address, recipient_bsc_address, fee_type, amount)
    VALUES (p_block_timestamp, v_external_address, v_recipient, v_fee_type, v_fee_amount)
    ON CONFLICT (token_external_address, recipient_bsc_address) DO UPDATE
        SET amount = fees_transferred.amount + v_fee_amount,
            updated_at = excluded.updated_at;

    RAISE DEBUG 'FeeTransfer processed: token=%, recipient=%', v_external_address, v_recipient;
END;
$$ LANGUAGE plpgsql;
