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
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_pair_id := LOWER(p_topics[3]);
    v_direction := (decode_uint256(p_data, 0) != 0);
    v_input_amount := decode_uint256(p_data, 1);
    v_output_amount := decode_uint256(p_data, 2);
    v_fee := decode_uint256(p_data, 3);

    BEGIN
        v_token_external_address := decode_to_token_from_input(p_tx_input);
        v_base_token := decode_base_token_from_input(p_tx_input);
    EXCEPTION WHEN OTHERS THEN
        v_token_external_address := NULL;
        v_base_token := NULL;
    END;

    IF v_token_external_address IS NOT NULL AND length(v_token_external_address) > 0 THEN
        v_token_external_address := substring(v_token_external_address from 2);

        SELECT
            t.contract_address,
            t.base_token,
            bp.price_usd,
            t.external_address,
            t.total_supply,
            t."type",
            t.ticker
        INTO v_token_address, v_other_token, v_base_price_usd, v_token_external_address, v_total_supply, v_token_type, v_token_ticker
        FROM tokens t
                 CROSS JOIN base_token_prices bp
        WHERE (t.external_address = v_token_external_address)
          AND lower(bp.token_address) = lower(t.base_token);
        IF v_token_address IS NULL THEN
            RAISE WARNING 'Token with external_address % not found, skipping swap', v_token_external_address;
            RETURN;
        END IF;
    ELSE
        SELECT
            t.contract_address,
            t.base_token,
            bp.price_usd,
            t.external_address,
            t.total_supply,
            t."type",
            t.ticker
        INTO v_token_address, v_other_token, v_base_price_usd, v_token_external_address, v_total_supply, v_token_type, v_token_ticker
        FROM tokens t
                 LEFT JOIN base_token_prices bp ON lower(bp.token_address) = lower(t.base_token)
        WHERE (t.pair_id = v_pair_id);
        IF v_token_address IS NULL THEN
            RAISE WARNING 'Token with pair % not found, skipping swap', v_pair_id;
            RETURN;
        END IF;
        IF v_base_price_usd = 0 THEN
            RAISE WARNING 'Token base token % not found, skipping swap', v_other_token;
            RETURN;
        END IF;
    END IF;

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

    INSERT INTO token_swaps (
        created_at, transaction_hash, contract_address, external_address,
        user_blockchain_address, direction, input_amount, output_amount, fee, price_usd, log_index
    )
    VALUES (
               p_block_timestamp, p_transaction_hash, v_token_address, v_token_external_address,
               v_user_address, v_direction, v_input_amount, v_output_amount, v_fee, v_price_usd, p_log_index
           )
    ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING;

    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_base_price_usd, v_total_supply);

    IF v_token_type = 'profile' THEN
        PERFORM update_base_token_price(v_token_address, v_token_ticker, v_price_usd);
    END IF;
    RAISE DEBUG 'Swapped processed: token=%, user=%', v_token_address, v_user_address;
END;
$$ LANGUAGE plpgsql;




CREATE OR REPLACE FUNCTION update_base_token_price(
    p_token_address TEXT,
    p_token_ticker TEXT,
    p_price_usd usd_amount
) RETURNS VOID AS
$$
BEGIN
    WITH old_price AS (
        SELECT price_usd
        FROM base_token_prices
        WHERE token_address = $1
    ),
         updated AS (
             INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
                 VALUES (p_token_address, p_token_ticker, p_price_usd, NOW())
                 ON CONFLICT (token_address) DO UPDATE SET
                     price_usd = EXCLUDED.price_usd,
                     updated_at = EXCLUDED.updated_at,
                     token_symbol = EXCLUDED.token_symbol
                 RETURNING price_usd
         )
    INSERT INTO base_token_price_history (token_address, price_usd, created_at)
    SELECT p_token_address, p_price_usd, NOW()
    WHERE NOT EXISTS (SELECT 1 FROM old_price)
       OR (SELECT price_usd FROM old_price) != p_price_usd;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_swapped_uniswap(
    p_transaction_hash TEXT,
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT,
    p_address TEXT
) RETURNS VOID AS $$
DECLARE
    v_swapper TEXT;
    v_recipient TEXT;
    v_user_address TEXT;
    v_direction BOOLEAN;
    v_input_amount0 NUMERIC;
    v_input_amount1 NUMERIC;
    v_output_amount NUMERIC;
    v_input_amount NUMERIC;
    v_fee NUMERIC;
    v_price_usd usd_amount;
    v_base_price_usd usd_amount;
    v_token_external_address TEXT;
    v_base_token TEXT;
    v_token0_is_tc_token BOOLEAN;
    v_token_address TEXT;
    v_token_type TEXT;
    v_token_ticker TEXT;
    v_total_supply NUMERIC;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_input_amount0 := to_int256(decode_uint256(p_data, 0));
    v_input_amount1 := to_int256(decode_uint256(p_data, 1));
    SELECT
        t.contract_address,
        t.base_token,
        t.external_address,
        bp.price_usd,
        p.token0 = t.contract_address,
        p.fee,
        t.total_supply,
        t."type",
        t.ticker
    INTO v_token_address, v_base_token,v_token_external_address, v_base_price_usd, v_token0_is_tc_token, v_fee, v_total_supply,
         v_token_type, v_token_ticker
    FROM tokens t
             CROSS JOIN base_token_prices bp
             JOIN uniswap_pools p ON p.token0 = t.contract_address OR p.token1 = t.contract_address
    WHERE p.pool_address = p_address
      AND lower(bp.token_address) = lower(t.base_token);

    IF v_token_address IS NULL THEN
        RAISE WARNING 'Token with pool % not found, skipping swap', p_address;
        RETURN;
    END IF;

    IF v_base_price_usd IS NULL THEN
        RAISE WARNING 'base token % price not found, skipping swap for tx %',v_base_token, p_transaction_hash;
        RETURN;
    END IF;


    IF v_input_amount = 0 OR v_output_amount = 0 THEN
        RAISE WARNING 'Invalid swap amounts (input=%, output=%) for tx %, skipping', v_input_amount, v_output_amount, p_transaction_hash;
        RETURN;
    END IF;

    if (v_token0_is_tc_token = TRUE AND v_input_amount0 > 0) OR (v_token0_is_tc_token = FALSE AND v_input_amount1 > 0) THEN -- sell of tc token
        v_input_amount = v_input_amount0;
        v_output_amount = v_input_amount1; -- base
        v_direction = true;
    ELSE
        v_input_amount = v_input_amount1;
        v_output_amount = v_input_amount0;
        v_direction = false;
    END IF;
    v_input_amount = ABS(v_input_amount);
    v_output_amount = ABS(v_output_amount);
    IF v_direction = false THEN -- buy
        v_user_address := v_recipient;
        v_price_usd := (v_input_amount / v_output_amount) * v_base_price_usd;
    ELSE -- sell
        v_user_address = v_swapper;
        v_price_usd := (v_output_amount / v_input_amount) * v_base_price_usd;
    END IF;

    INSERT INTO token_swaps (
        created_at, transaction_hash, contract_address, external_address,
        user_blockchain_address, direction, input_amount, output_amount, fee, price_usd, log_index
    )
    VALUES (
               p_block_timestamp, p_transaction_hash, v_token_address, v_token_external_address,
               v_user_address, v_direction, v_input_amount, v_output_amount, v_fee, v_price_usd, p_log_index
           )
    ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING;

    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_base_price_usd, v_total_supply);
    IF v_token_type = 'profile' THEN
        PERFORM update_base_token_price(v_token_address, v_token_ticker, v_price_usd);
    END IF;
    RAISE DEBUG 'Uniswap swap processed: token=%, user=%', v_token_address, v_user_address;
END;
$$ LANGUAGE plpgsql;
