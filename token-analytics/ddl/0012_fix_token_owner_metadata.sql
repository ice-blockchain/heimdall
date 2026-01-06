-- SPDX-License-Identifier: ice License 1.0

DROP FUNCTION IF EXISTS update_market_cap_and_position(
    TIMESTAMP,
    TEXT,
    TEXT,
    TEXT,
    BOOLEAN,
    NUMERIC,
    NUMERIC,
    NUMERIC,
    NUMERIC,
    NUMERIC
);

WITH duplicates AS (
    SELECT content_author_id,
           username,
           ROW_NUMBER() OVER (PARTITION BY username ORDER BY created_at ASC) as rn
    FROM users
)
UPDATE users
SET username = users.username || '_' || duplicates.rn
FROM duplicates
WHERE users.content_author_id = duplicates.content_author_id
  AND duplicates.rn > 1;

UPDATE users
SET content_author_id = '0x' || md5(id || master_pubkey)::text
WHERE content_author_id = '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_username_key'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT users_username_key UNIQUE (username);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_content_author_id_not_empty'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT users_content_author_id_not_empty CHECK (content_author_id <> '');
    END IF;
END $$;

CREATE OR REPLACE FUNCTION process_bonded_token_created(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT
) RETURNS VOID AS $$
DECLARE
    v_token_address TEXT;
    v_external_address TEXT;
    v_platform platform_type;
    v_platform_prefix TEXT;
    v_total_supply NUMERIC;
    v_token_type TEXT;
    v_token_symbol TEXT;
    v_token_title TEXT;
    v_creator_address TEXT;
    v_affiliate_address TEXT;
BEGIN
    IF array_length(p_topics, 1) < 2 THEN
        RETURN;
    END IF;

    v_token_address := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_token_title := decode_string_abi(p_data, 0); -- name
    v_token_symbol := decode_string_abi(p_data, 1); -- symbol
    -- v_creator_token_address at index 2 (not used here)
    v_platform_prefix := CHR(decode_uint256(p_data, 3)::INT); -- index 3
    v_external_address := decode_string_abi(p_data, 4);
    v_creator_address := LOWER('0x' || substring(p_data from (5*64+27) for 40));
    v_affiliate_address := LOWER('0x' || substring(p_data from (6*64+27) for 40));
    v_total_supply := decode_uint256(p_data, 7);

    IF v_external_address IS NULL OR v_external_address = '' THEN
        RAISE WARNING 'Empty external address, skipping token creation';
        RETURN;
    END IF;

    v_platform := get_platform_group(v_platform_prefix);

    IF v_platform IS NULL THEN
        RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address;
        RETURN;
    END IF;

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
            RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address;
            RETURN;
    END CASE;

    IF v_token_type IS NULL THEN
        RAISE WARNING 'Failed to determine token type for %, skipping token creation', v_external_address;
        RETURN;
    END IF;

    INSERT INTO tokens (
        created_at, updated_at, contract_address, external_address, platform, affiliate_bsc_address,
        ticker, title, total_supply, content_author_id, type, bnb_bsc_metadata_owner_address, log_index
    )
    VALUES (
        p_block_timestamp,
        p_block_timestamp,
        v_token_address,
        v_external_address,
        v_platform,
        v_affiliate_address,
        CASE
            WHEN v_platform = 'ionconnect' AND v_token_type IN ('post', 'video', 'article')
                THEN v_external_address
            ELSE v_token_symbol
        END,
        v_token_title,
        v_total_supply,
        v_creator_address,
        v_token_type,
        v_creator_address,
        p_log_index
    )
    ON CONFLICT (contract_address) DO UPDATE SET
        updated_at = EXCLUDED.updated_at,
        external_address = COALESCE(EXCLUDED.external_address, tokens.external_address),
        total_supply = COALESCE(EXCLUDED.total_supply, tokens.total_supply),
        bnb_bsc_metadata_owner_address = COALESCE(EXCLUDED.bnb_bsc_metadata_owner_address, tokens.bnb_bsc_metadata_owner_address),
        platform = COALESCE(EXCLUDED.platform, tokens.platform),
        ticker = COALESCE(EXCLUDED.ticker, tokens.ticker),
        title = COALESCE(EXCLUDED.title, tokens.title),
        affiliate_bsc_address = COALESCE(EXCLUDED.affiliate_bsc_address, tokens.affiliate_bsc_address),
        content_author_id = COALESCE(EXCLUDED.content_author_id, tokens.content_author_id),
        type = COALESCE(EXCLUDED.type, tokens.type),
        log_index = COALESCE(EXCLUDED.log_index, tokens.log_index);

    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
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
    p_base_price_usd NUMERIC,
    p_total_supply NUMERIC
) RETURNS VOID AS $$
DECLARE
    v_user_external_address TEXT;
    v_market_cap_usd usd_amount;
    v_market_cap_ion NUMERIC;
    v_price_ion NUMERIC;
    v_cost_usd usd_amount;
    v_realized_usd usd_amount;
    v_buyer_username TEXT;
    v_buyer_display_name TEXT;
    v_platform platform_type;
    v_owner_avatar TEXT;
    v_owner_username TEXT;
    v_owner_display_name TEXT;
    v_owner_content_author_id TEXT;
    v_author_pubkey TEXT;
    v_owner_external_address TEXT;
BEGIN
    IF p_direction = false THEN
        v_price_ion := p_input_amount / p_output_amount;
    ELSE
        v_price_ion := p_output_amount / p_input_amount;
    END IF;

    v_market_cap_usd := p_price_usd * (p_total_supply / 1e18);
    v_market_cap_ion := v_price_ion * p_total_supply;

    -- Buyer's data for user_token_positions and lookup
    SELECT external_address, username, display_name
    INTO v_user_external_address, v_buyer_username, v_buyer_display_name
    FROM users
    WHERE LOWER(content_author_id) = LOWER(p_user_blockchain_address);

    -- Token owner's metadata
    v_author_pubkey := split_part(p_token_external_address, ':', 1);
    IF v_author_pubkey = '0' THEN
        v_owner_external_address := p_token_external_address;
    ELSIF v_author_pubkey <> p_token_external_address THEN
        v_author_pubkey := split_part(p_token_external_address, ':', 2);
        v_owner_external_address := '0:' || v_author_pubkey || ':';
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

    v_cost_usd := (p_input_amount / 1e18) * p_base_price_usd;

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
        v_realized_usd := (p_output_amount / 1e18) * p_base_price_usd;

        UPDATE user_token_positions
        SET amount = GREATEST(amount - p_input_amount, 0),
            total_realized_usd = COALESCE(total_realized_usd, 0) + v_realized_usd,
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
END; $$ LANGUAGE plpgsql;

