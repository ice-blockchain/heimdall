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
    v_price_in_base NUMERIC;
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
        v_price_in_base := (v_input_amount / v_output_amount);
        v_price_usd := v_price_in_base * v_base_price_usd;
    ELSE -- sell
        v_price_in_base := (v_output_amount / v_input_amount);
        v_price_usd := v_price_in_base * v_base_price_usd;
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
    -- TODO: check what price to use for positions / avg price from here or spot and
    -- update avg_buy_price_usd, total_invested_usd, total_realized_usd from UPDATE token_swaps SET curve_price_usd ...
    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_base_price_usd, v_total_supply);
    IF v_token_type = 'profile' THEN
        PERFORM update_base_token_price(v_token_address, v_token_ticker, v_price_usd, v_price_in_base);
    END IF;
    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Successfully processed | tx=% | token=% | user=% | external=%',
        p_transaction_hash, v_token_address, v_user_address, v_token_external_address;
END;
$$ LANGUAGE plpgsql;
