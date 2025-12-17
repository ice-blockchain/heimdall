
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'users' AND column_name = 'blockchain_address') THEN
        ALTER TABLE users RENAME COLUMN blockchain_address TO content_author_id;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'tokens' AND column_name = 'creator_blockchain_address') THEN
        ALTER TABLE tokens RENAME COLUMN creator_blockchain_address TO content_author_id;
    END IF;
END $$;

DROP INDEX IF EXISTS idx_users_blockchain_address_lower;
CREATE INDEX IF NOT EXISTS idx_users_content_author_id_lower ON users (LOWER(content_author_id));

DROP INDEX IF EXISTS idx_tokens_creator;
CREATE INDEX IF NOT EXISTS idx_tokens_creator ON tokens (content_author_id);

CREATE OR REPLACE FUNCTION update_user_profile_from_token() RETURNS trigger AS $$
BEGIN
    UPDATE tokens
    SET lookup = LOWER(TRIM(
        COALESCE(NEW.contract_address, '') || ' ' ||
        COALESCE(NEW.ticker, '') || ' ' ||
        COALESCE(NEW.username, '') || ' ' ||
        COALESCE(NEW.display_name, '')
    ))
    WHERE LOWER(content_author_id) = LOWER(NEW.content_author_id);

    RETURN NEW;
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
    p_ion_price_usd NUMERIC
) RETURNS VOID AS $$
    DECLARE
        v_user_external_address TEXT;
        v_delta_market_cap usd_amount;
        v_token_amount NUMERIC;
        v_sign NUMERIC;
        v_cost_usd usd_amount;
        v_username TEXT;
        v_display_name TEXT;
        v_avatar TEXT;
        v_token_type TEXT;
        v_platform platform_type;
    BEGIN
    IF p_direction = false THEN
        v_token_amount := p_output_amount;
        v_sign := 1.0;
    ELSE
        v_token_amount := p_input_amount;
        v_sign := -1.0;
    END IF;

    v_delta_market_cap := v_sign * (v_token_amount / 1e18) * p_price_usd;


    SELECT external_address, username, display_name, avatar
    INTO v_user_external_address, v_username, v_display_name, v_avatar
    FROM users
    WHERE LOWER(content_author_id) = LOWER(p_user_blockchain_address);

    SELECT type, platform INTO v_token_type, v_platform FROM tokens WHERE contract_address = p_token_address;

    UPDATE tokens t
    SET price_usd = p_price_usd,
        market_cap_usd = GREATEST(market_cap_usd + v_delta_market_cap, 0),
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

CREATE OR REPLACE FUNCTION process_bonded_token_created(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT
) RETURNS VOID AS $$
DECLARE
    v_token_address TEXT;
    v_external_address TEXT;
    v_external_address_raw TEXT;
    v_platform platform_type;
    v_platform_prefix TEXT;
    v_total_supply NUMERIC;
    v_token_type TEXT;
    v_username TEXT;
    v_display_name TEXT;
    v_lookup_value TEXT;
    v_kind INT;
    v_parts TEXT[];
    v_token_symbol TEXT;
BEGIN
    IF array_length(p_topics, 1) < 2 THEN
        RETURN;
    END IF;

    v_token_address := LOWER('0x' || substring(p_topics[2] from 27 for 40));

    v_token_symbol := decode_string_abi(p_data, 1);
    v_external_address_raw := decode_string_abi(p_data, 2);
    v_total_supply := decode_uint256(p_data, 3);

    IF v_external_address_raw IS NULL OR v_external_address_raw = '' THEN
        RAISE WARNING 'Empty external address, skipping token creation';
        RETURN;
    END IF;

    v_platform_prefix := substring(v_external_address_raw, 1, 1);
    v_platform := get_platform_group(v_external_address_raw);

    IF v_platform IS NULL THEN
        RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address_raw;
        RETURN;
    END IF;

    v_external_address := substring(v_external_address_raw from 2);

    CASE
        WHEN v_platform_prefix IN ('a', 'z') THEN
            v_token_type := 'profile';
        WHEN v_platform_prefix IN ('b', 'y') THEN
            v_token_type := 'post';
        WHEN v_platform_prefix IN ('c', 'x') THEN
            v_token_type := 'video';
        WHEN v_platform_prefix IN ('d', 'w') THEN
            v_token_type := 'article';
        ELSE
            RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address_raw;
            RETURN;
    END CASE;

    -- For ALL tokens, content_author_id will be populated from first Swapped event
    IF v_token_type IS NULL THEN
        RAISE WARNING 'Failed to determine token type for %, skipping token creation', v_external_address;
        RETURN;
    END IF;

    INSERT INTO tokens (
        created_at, updated_at, contract_address, external_address, platform,
        ticker, total_supply, content_author_id, type, log_index
    )
    VALUES (
        p_block_timestamp,
        p_block_timestamp,
        v_token_address,
        v_external_address,
        v_platform,
        CASE
            WHEN v_platform = 'ionconnect' AND v_token_type IN ('post', 'video', 'article')
            THEN v_external_address
            ELSE v_token_symbol
        END,
        v_total_supply,
        NULL, -- Will be filled on first swap
        v_token_type,
        p_log_index
    )
    ON CONFLICT (external_address) DO UPDATE SET
        updated_at = EXCLUDED.updated_at,
        total_supply = EXCLUDED.total_supply,
        contract_address = EXCLUDED.contract_address,
        platform = EXCLUDED.platform,
        ticker = COALESCE(EXCLUDED.ticker, tokens.ticker),
        log_index = COALESCE(EXCLUDED.log_index, tokens.log_index);

    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
END;
$$ LANGUAGE plpgsql;

