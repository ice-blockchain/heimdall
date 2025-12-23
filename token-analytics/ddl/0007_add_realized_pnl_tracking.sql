-- SPDX-License-Identifier: ice License 1.0

-- Add total_realized_usd column (stores total revenue from sells, not PnL)
ALTER TABLE user_token_positions ADD COLUMN IF NOT EXISTS total_realized_usd NUMERIC(78, 18) DEFAULT 0;

-- Update update_market_cap_and_position function to track realized revenue from sells
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
        v_realized_usd usd_amount;
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
    v_market_cap_ion := v_price_ion * p_total_supply;

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
            amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, updated_at
        )
        VALUES (
                   p_user_blockchain_address, p_token_address, p_token_external_address,
                   v_user_external_address,
                   p_output_amount, p_price_usd, v_cost_usd, 0, p_block_timestamp
               )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
            amount = user_token_positions.amount + EXCLUDED.amount,
            total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
            avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) /
                                NULLIF((user_token_positions.amount + EXCLUDED.amount)::NUMERIC, 0),
            updated_at = EXCLUDED.updated_at,
            user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    ELSE -- sell
        -- Calculate realized revenue (not PnL, just revenue from sale)
        v_realized_usd := (p_output_amount / 1e18) * p_ion_price_usd;

        UPDATE user_token_positions
        SET amount = GREATEST(amount - p_input_amount, 0),
            total_realized_usd = COALESCE(total_realized_usd, 0) + v_realized_usd,
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
    END; $$ LANGUAGE plpgsql;
