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
    v_ion_price_usd usd_amount;
    v_token_external_address TEXT;
    v_base_token TEXT;
    v_other_token TEXT;
    v_token_address TEXT;
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
            t.total_supply
        INTO v_token_address, v_other_token, v_ion_price_usd, v_token_external_address, v_total_supply
        FROM tokens t
        CROSS JOIN base_token_prices bp
        WHERE (t.external_address = v_token_external_address)
            AND bp.token_symbol = 'ION';
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
            t.total_supply
        INTO v_token_address, v_other_token, v_ion_price_usd, v_token_external_address, v_total_supply
        FROM tokens t
        CROSS JOIN base_token_prices bp
        WHERE (t.pair_id = v_pair_id)
          AND bp.token_symbol = 'ION';
        IF v_token_address IS NULL THEN
            RAISE WARNING 'Token with pair % not found, skipping swap', v_pair_id;
            RETURN;
        END IF;
    END IF;

    IF v_ion_price_usd IS NULL THEN
        RAISE WARNING 'ION price not found, skipping swap for tx %', p_transaction_hash;
        RETURN;
    END IF;

    v_user_address := v_swapper;

    IF v_input_amount = 0 OR v_output_amount = 0 THEN
        RAISE WARNING 'Invalid swap amounts (input=%, output=%) for tx %, skipping', v_input_amount, v_output_amount, p_transaction_hash;
        RETURN;
    END IF;

    IF v_direction = false THEN -- buy
        v_price_usd := (v_input_amount / v_output_amount) * v_ion_price_usd;
    ELSE -- sell
        v_price_usd := (v_output_amount / v_input_amount) * v_ion_price_usd;
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
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_ion_price_usd, v_total_supply);


    RAISE DEBUG 'Swapped processed: token=%, user=%', v_token_address, v_user_address;
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
    v_ion_price_usd usd_amount;
    v_token_external_address TEXT;
    v_base_token TEXT;
    v_token0_is_tc_token BOOLEAN;
    v_token_address TEXT;
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
        t.total_supply
    INTO v_token_address, v_base_token,v_token_external_address, v_ion_price_usd, v_token0_is_tc_token, v_fee, v_total_supply
    FROM tokens t
             CROSS JOIN base_token_prices bp
             JOIN uniswap_pools p ON p.token0 = t.contract_address OR p.token1 = t.contract_address
    WHERE p.pool_address = p_address
      AND bp.token_symbol = 'ION';

    IF v_token_address IS NULL THEN
        RAISE WARNING 'Token with pool % not found, skipping swap', p_address;
        RETURN;
    END IF;

    IF v_ion_price_usd IS NULL THEN
        RAISE WARNING 'ION price not found, skipping swap for tx %', p_transaction_hash;
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
        v_price_usd := (v_input_amount / v_output_amount) * v_ion_price_usd;
    ELSE -- sell
        v_user_address = v_swapper;
        v_price_usd := (v_output_amount / v_input_amount) * v_ion_price_usd;
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
                                            v_direction, v_input_amount, v_output_amount, v_price_usd, v_ion_price_usd, v_total_supply);

    RAISE DEBUG 'Uniswap swap processed: token=%, user=%', v_token_address, v_user_address;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_market_cap_and_position(
    p_block_timestamp TIMESTAMP,
    p_user_blockchain_address TEXT,
    p_token_address TEXT,
    p_token_external_address TEXT,
    p_direction BOOLEAN,
    p_input_amount NUMERIC,
    p_output_amount NUMERIC,
    p_price_usd NUMERIC,
    p_ion_price_usd NUMERIC,
    p_total_supply NUMERIC
) RETURNS VOID AS $$
    DECLARE
        v_user_external_address TEXT;
        v_market_cap_usd usd_amount;
        v_market_cap_ion NUMERIC;
        v_price_ion NUMERIC;
        v_cost_usd usd_amount;
        v_username TEXT;
        v_display_name TEXT;
        v_avatar TEXT;
        v_token_type TEXT;
        v_platform platform_type;
    BEGIN
    IF p_direction = false THEN
        v_price_ion := p_input_amount / p_output_amount;
    ELSE
        v_price_ion := p_output_amount / p_input_amount;
    END IF;

    v_market_cap_usd := p_price_usd * (p_total_supply / 1e18);
    v_market_cap_ion := v_price_ion * (p_total_supply / 1e18);

    SELECT external_address, username, display_name, avatar
    INTO v_user_external_address, v_username, v_display_name, v_avatar
    FROM users
    WHERE LOWER(content_author_id) = LOWER(p_user_blockchain_address);

    SELECT type, platform INTO v_token_type, v_platform FROM tokens WHERE contract_address = p_token_address;

    UPDATE tokens t
    SET price_usd = p_price_usd,
        market_cap_usd = v_market_cap_usd,
        market_cap = v_market_cap_ion,
        updated_at = p_block_timestamp,
        content_author_id = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
            THEN p_user_blockchain_address
            ELSE t.content_author_id
        END,
        ticker = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
                 AND v_platform = 'ionconnect' AND v_token_type = 'profile'
                 AND v_username IS NOT NULL
            THEN v_username
            ELSE t.ticker
        END,
        title = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
                 AND v_platform = 'ionconnect' AND v_display_name IS NOT NULL
            THEN v_display_name
            ELSE t.title
        END,
        image_url = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false
                 AND v_avatar IS NOT NULL
            THEN v_avatar
            ELSE t.image_url
        END,
        lookup = CASE
            WHEN t.content_author_id IS NULL AND p_direction = false AND v_username IS NOT NULL THEN
                LOWER(TRIM(
                    COALESCE(t.contract_address, '') || ' ' ||
                    COALESCE(t.ticker, '') || ' ' ||
                    COALESCE(v_username, '') || ' ' ||
                    COALESCE(v_display_name, '')
                ))
            ELSE t.lookup
        END
    WHERE contract_address = p_token_address;

    v_cost_usd := (p_input_amount / 1e18) * p_ion_price_usd;

    IF p_direction = false THEN -- buy
        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, avg_buy_price_usd, total_invested_usd, updated_at
        )
        VALUES (
                   p_user_blockchain_address, p_token_address, p_token_external_address,
                   v_user_external_address,
                   p_output_amount, p_price_usd, v_cost_usd, p_block_timestamp
               )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
                                                                    amount = user_token_positions.amount + EXCLUDED.amount,
                                                                    total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
                                                                    avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) /
                                                                                        NULLIF((user_token_positions.amount + EXCLUDED.amount)::NUMERIC, 0),
                                                                    updated_at = EXCLUDED.updated_at,
                                                                    user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    ELSE -- sell
        UPDATE user_token_positions
        SET amount = GREATEST(amount - p_input_amount, 0),
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
    END; $$ LANGUAGE plpgsql;

