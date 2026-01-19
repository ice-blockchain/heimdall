-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION update_market_cap_and_position(
    p_block_timestamp TIMESTAMP,
    p_user_blockchain_address TEXT,
    p_token_address TEXT,
    p_token_external_address TEXT,
    p_direction BOOLEAN,
    p_input_amount NUMERIC,
    p_output_amount NUMERIC,
    p_price_usd usd_amount,
    p_ion_price_usd usd_amount,
    p_total_supply NUMERIC,
    p_base_token_address TEXT,
    p_fee_amount NUMERIC
) RETURNS VOID AS $$
DECLARE
    v_user_external_address TEXT;
    v_market_cap_usd usd_amount;
    v_market_cap_ion NUMERIC;
    v_cost_usd NUMERIC;
    v_realized_usd NUMERIC;
    v_owner_external_address TEXT;
    v_owner_avatar TEXT;
    v_owner_username TEXT;
    v_owner_display_name TEXT;
    v_platform TEXT;
    v_owner_content_author_id TEXT;
BEGIN
    SELECT external_address INTO v_user_external_address
    FROM users
    WHERE LOWER(content_author_id) = LOWER(p_user_blockchain_address);

    v_market_cap_ion := (p_total_supply / 1e18) * p_price_usd / p_ion_price_usd;
    v_market_cap_usd := (p_total_supply / 1e18) * p_price_usd;

    IF POSITION(':' IN p_token_external_address) > 0 THEN
        v_owner_external_address := SPLIT_PART(p_token_external_address, ':', 1) || ':' || SPLIT_PART(p_token_external_address, ':', 2) || ':';
    ELSE
        v_owner_external_address := p_token_external_address;
    END IF;

    SELECT avatar, username, display_name, platform_group, content_author_id
    INTO v_owner_avatar, v_owner_username, v_owner_display_name, v_platform, v_owner_content_author_id
    FROM users
    WHERE external_address = v_owner_external_address;

    UPDATE tokens t
    SET price_usd = p_price_usd,
        market_cap_usd = v_market_cap_usd,
        market_cap = v_market_cap_ion,
        updated_at = p_block_timestamp,
        image_url = CASE
            WHEN t.image_url IS NULL AND p_direction = false
                     AND v_platform = 'ionconnect' AND v_owner_avatar IS NOT NULL
                THEN v_owner_avatar
            ELSE t.image_url
            END,
        lookup = CASE
            WHEN (t.lookup IS NULL OR t.lookup = '') AND p_direction = false THEN
                LOWER(TRIM(
                        COALESCE(t.contract_address, '') || ' ' ||
                        COALESCE(t.ticker, '') || ' ' ||
                        COALESCE(v_owner_username, '') || ' ' ||
                        COALESCE(v_owner_display_name, '')
                    ))
            ELSE t.lookup
            END
    WHERE contract_address = p_token_address;

    v_cost_usd := (p_input_amount / 1e18) * p_ion_price_usd;

    IF p_direction = false THEN -- buy
        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, updated_at
        )
        VALUES (
                   p_user_blockchain_address, p_token_address, p_token_external_address,
                   v_user_external_address,
                   0, p_price_usd, v_cost_usd, 0, p_block_timestamp
               )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
            total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
            avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) /
                                NULLIF((user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) / NULLIF(p_price_usd, 0), 0),
            updated_at = EXCLUDED.updated_at,
            user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    ELSE -- sell
        v_realized_usd := (p_output_amount / 1e18) * p_ion_price_usd;

        -- Update only realized USD (amount will be updated via RPC)
        UPDATE user_token_positions
        SET total_realized_usd = COALESCE(total_realized_usd, 0) + v_realized_usd,
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
END; $$ LANGUAGE plpgsql;



