-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION process_erc20_transfer(
    p_contract_address TEXT,
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_amount NUMERIC;
    v_recipient TEXT;
    v_external_address TEXT;
    v_fee_type TEXT;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_amount := decode_uint256(p_data, 0);
    IF v_recipient = '0x0000000000000000000000000000000000000000' THEN
        v_recipient := '0x0000000000000000000000000000000000696f6e';
    END IF;
    IF v_recipient != '0x0000000000000000000000000000000000696f6e' THEN -- handle only burned for now to increase burned fee
        RETURN;
    END IF;
    SELECT
        t.external_address
    INTO v_external_address
    FROM tokens t
    WHERE t.contract_address = p_contract_address;
    IF v_external_address IS NULL THEN
        RAISE WARNING 'Token with contract_address % not found, skipping fee erc20 processing', p_contract_address;
        RETURN;
    END IF;
    v_fee_type := 'burn';

    INSERT INTO fees_transferred (updated_at, token_external_address, recipient_bsc_address, fee_type, amount)
    VALUES (p_block_timestamp, v_external_address, v_recipient, v_fee_type, v_amount)
    ON CONFLICT (token_external_address, recipient_bsc_address) DO UPDATE
        SET amount = fees_transferred.amount + v_amount,
            updated_at = excluded.updated_at;

    RAISE DEBUG 'Transfer (erc20) processed: token=%, recipient=%, amount=%', v_external_address, v_recipient, v_amount;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_tx_log_event()
    RETURNS TRIGGER AS $$
DECLARE
    v_block_timestamp TIMESTAMP;
    v_tx_input TEXT;
    v_from TEXT;
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();

    SELECT block_timestamp, input, from_address INTO v_block_timestamp, v_tx_input, v_from
    FROM transactions
    WHERE transaction_hash = NEW.transaction_hash;

    CASE NEW.topic0
        WHEN '0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd' THEN -- BondingTokenCreated
        PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_tx_input, v_from, v_block_timestamp, NEW.log_index);
        WHEN '0x908a4168fc7576885b681f3b0594297fa8118a2bca55899ac9ef3229438dbb04' THEN -- PairRegistered
        PERFORM process_pair_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0' THEN -- Swapped
        PERFORM process_swapped(NEW.transaction_hash, NEW.topics, NEW.data, v_tx_input, v_block_timestamp, NEW.log_index, NEW.address);
        WHEN '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118' THEN -- PoolCreated (uniswap)
        PERFORM process_pool_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67' THEN -- Swap (uniswap)
        PERFORM process_swapped_uniswap(NEW.transaction_hash, NEW.topics, NEW.data, v_block_timestamp, NEW.log_index, NEW.address);
        WHEN '0xbda77c1230f2354807b9e8307932c78ac43f6b38ea2e10d9886aa30c958300f5' THEN -- FeeTransfer
        PERFORM process_fee_transfer(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef' THEN -- Transfer (regular ERC20)
        PERFORM process_erc20_transfer(v_from, NEW.topics, NEW.data, v_block_timestamp);
        ELSE
            NULL;
        END CASE;

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[TRIGGER][ELAPSED] process_tx_log_event: Processed log | tx=% | topic0=% | elapsed_ms=%',
        NEW.transaction_hash, NEW.topic0, ROUND(v_elapsed_ms, 2);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;