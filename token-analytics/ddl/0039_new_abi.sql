-- SPDX-License-Identifier: ice License 1.0

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
    v_base_price_usd usd_amount;
    v_token_external_address TEXT;
    v_base_token TEXT;
    v_other_token TEXT;
    v_token_address TEXT;
    v_token_type TEXT;
    v_token_ticker TEXT;
    v_total_supply NUMERIC;
    v_burned NUMERIC;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Invalid topics array length: % | tx=%', array_length(p_topics, 1), p_transaction_hash;
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_pair_id := LOWER(p_topics[3]);
    v_direction := (decode_uint256(p_data, 0) != 0);
    -- Event includes feeToken at index 1:
    -- Word 0: direction, Word 1: inputAmount, Word 2: outputAmount, Word 3: fee
    v_input_amount := decode_uint256(p_data, 1);
    v_output_amount := decode_uint256(p_data, 2);
    v_fee := decode_uint256(p_data, 3);

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Processing tx=% | swapper=% | pair_id=% | direction=% | input=% | output=% | fee=%',
        p_transaction_hash, v_swapper, v_pair_id, v_direction, v_input_amount, v_output_amount, v_fee;


    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Processing tx=% | swapper=% | pair_id=% | direction=% | input=% | output=% | fee=%',
        p_transaction_hash, v_swapper, v_pair_id, v_direction, v_input_amount, v_output_amount, v_fee;

    BEGIN
        v_token_external_address := decode_to_token_from_input(p_tx_input);
        v_base_token := decode_base_token_from_input(p_tx_input);
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Decoded from tx input | tx=% | token_external=% | base_token=%',
            p_transaction_hash, v_token_external_address, v_base_token;
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Failed to decode from tx input | tx=% | error=%', p_transaction_hash, SQLERRM;
        v_token_external_address := NULL;
        v_base_token := NULL;
    END;

    -- Try to find token by external_address + pair_id first
    IF v_token_external_address IS NOT NULL AND length(v_token_external_address) > 0 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Looking up by external_address + pair_id | tx=% | external=% | pair_id=%',
            p_transaction_hash, v_token_external_address, v_pair_id;

        SELECT
            t.contract_address,
            t.base_token,
            bp.price_usd,
            t.external_address,
            t.total_supply,
            t."type",
            t.ticker,
            COALESCE(burned.amount, 0) AS burned
        INTO v_token_address, v_other_token, v_base_price_usd, v_token_external_address, v_total_supply, v_token_type, v_token_ticker, v_burned
        FROM tokens t
                 LEFT JOIN base_token_prices bp ON lower(bp.token_address) = lower(t.base_token)
                 LEFT JOIN fees_transferred burned ON burned.token_external_address = t.external_address AND burned.recipient_bsc_address = '0x0000000000000000000000000000000000696f6e'
        WHERE t.external_address = v_token_external_address
          AND t.pair_id = v_pair_id; -- Verify pair_id matches to handle double swap correctly
    END IF;

    -- If not found by external_address + pair_id (double swap first event) or no external_address, find by pair_id only
    IF v_token_address IS NULL THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Looking up by pair_id only | tx=% | pair_id=%', p_transaction_hash, v_pair_id;

        SELECT
            t.contract_address,
            t.base_token,
            bp.price_usd,
            t.external_address,
            t.total_supply,
            t."type",
            t.ticker,
            COALESCE(burned.amount, 0) AS burned
        INTO v_token_address, v_other_token, v_base_price_usd, v_token_external_address, v_total_supply, v_token_type, v_token_ticker, v_burned
        FROM tokens t
                 LEFT JOIN base_token_prices bp ON lower(bp.token_address) = lower(t.base_token)
                 LEFT JOIN fees_transferred burned ON burned.token_external_address = t.external_address AND burned.recipient_bsc_address = '0x0000000000000000000000000000000000696f6e'
        WHERE t.pair_id = v_pair_id;

        IF v_token_address IS NULL THEN
            RAISE WARNING 'Token with pair_id % not found, skipping swap', v_pair_id;
            RETURN;
        END IF;
        IF v_base_price_usd IS NULL OR v_base_price_usd = 0 THEN
            RAISE WARNING 'Token base token % not found, skipping swap', v_other_token;
            RETURN;
        END IF;
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Found token | tx=% | token=% | external=% | base_price_usd=% | type=%',
        p_transaction_hash, v_token_address, v_token_external_address, v_base_price_usd, v_token_type;

    IF v_base_price_usd IS NULL THEN
        -- TODO: single purchase of creator and content tokens - needs to be checked how it looks like on blockchain
        RAISE WARNING 'Base price not found, skipping swap for tx %', p_transaction_hash;
        RETURN;
    END IF;

    v_user_address := v_swapper;

    IF v_input_amount = 0 OR v_output_amount = 0 THEN
        RAISE WARNING 'Invalid swap amounts (input=%, output=%) for tx %, skipping', v_input_amount, v_output_amount, p_transaction_hash;
        RETURN;
    END IF;

    IF v_direction = false THEN -- buy
        v_price_usd := (v_input_amount / v_output_amount) * v_base_price_usd;
    ELSE -- sell
        v_price_usd := (v_output_amount / v_input_amount) * v_base_price_usd;
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Calculated price | tx=% | token=% | price_usd=% | direction=%',
        p_transaction_hash, v_token_address, v_price_usd, v_direction;

    INSERT INTO token_swaps (
        created_at, transaction_hash, contract_address, external_address,
        user_blockchain_address, direction, input_amount, output_amount, fee, price_usd, log_index
    )
    VALUES (
               p_block_timestamp, p_transaction_hash, v_token_address, v_token_external_address,
               v_user_address, v_direction, v_input_amount, v_output_amount, v_fee, v_price_usd, p_log_index
           )
    ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING;
    v_total_supply = v_total_supply - v_burned;
    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_base_price_usd, v_total_supply);

    IF v_token_type = 'profile' THEN
        PERFORM update_base_token_price(v_token_address, v_token_ticker, v_price_usd);
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Successfully processed | tx=% | token=% | user=% | external=%',
        p_transaction_hash, v_token_address, v_user_address, v_token_external_address;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION process_pair_registered(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_base_token TEXT;
    v_pair_id TEXT;
    v_other_token TEXT;
    v_price_model TEXT;
    v_start_price NUMERIC;
    v_end_price NUMERIC;
    v_fee_in_other_token BOOL;
BEGIN
    IF array_length(p_topics, 1) < 4 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Invalid topics array length: %', array_length(p_topics, 1);
        RETURN;
    END IF;

    v_pair_id := LOWER(p_topics[2]);
    v_base_token := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_other_token := LOWER('0x' || substring(p_topics[4] from 27 for 40));
    v_fee_in_other_token := (decode_uint256(p_data, 0) != 0);
    v_price_model := LOWER('0x' || substring(p_data from 64+27 for 64+40)); -- priceModel at offset 1
    v_start_price := decode_uint256(p_data, 2); -- startPrice at offset 2
    v_end_price := decode_uint256(p_data, 3); -- endPrice at offset 3

    RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Processing token=% | pair_id=% | base_token=% | price_model=% | start_price=% | end_price=%',
        v_other_token, v_pair_id, v_base_token, v_price_model, v_start_price, v_end_price;

    UPDATE tokens
    SET
        base_token = v_base_token,
        pair_id = v_pair_id,
        price_model = v_price_model,
        start_price = v_start_price,
        end_price = v_end_price,
        updated_at = p_block_timestamp
    WHERE LOWER(contract_address) = v_other_token;

    RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Successfully processed token=% | pair_id=%', v_other_token, v_pair_id;
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
        ELSE
            NULL;
        END CASE;

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[TRIGGER][ELAPSED] process_tx_log_event: Processed log | tx=% | topic0=% | elapsed_ms=%',
        NEW.transaction_hash, NEW.topic0, ROUND(v_elapsed_ms, 2);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;