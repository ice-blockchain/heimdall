-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION get_platform_group(p_prefix TEXT)
RETURNS platform_type AS $$
BEGIN
    IF p_prefix IN ('z','y','x','w','v') THEN
        RETURN 'xcom'::platform_type;
    ELSIF p_prefix IN ('a','b','c','d','e') THEN
        RETURN 'ionconnect'::platform_type;
    ELSE
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION process_bonded_token_created(
    p_topics TEXT[],
    p_data TEXT,
    p_tx_input TEXT,
    p_fee_sponsor_address TEXT,
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
    v_function_selector TEXT;
    handleops_selector TEXT := '74fa4121';
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    IF array_length(p_topics, 1) < 2 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] BondedTokenCreated: Invalid topics array length: %', array_length(p_topics, 1);
        RETURN;
    END IF;

    v_token_address := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_token_title := decode_string_abi(p_data, 0); -- name
    v_token_symbol := decode_string_abi(p_data, 1); -- symbol
    v_platform_prefix := CHR(decode_uint256(p_data, 2)::INT); -- externalType
    v_external_address := decode_string_abi(p_data, 3); -- externalAddress
    v_total_supply := decode_uint256(p_data, 4); -- totalSupply
    v_creator_address := LOWER('0x' || substring(p_data from (5*64+27) for 40)); -- creatorAddress
    v_affiliate_address := LOWER('0x' || substring(p_data from (6*64+27) for 40)); -- affiliateAddress

    RAISE NOTICE '[EVENT_PROCESSOR] BondedTokenCreated: Processing token=% | external=% | platform_prefix=% | symbol=% | title=% | creator=% | affiliate=%',
        v_token_address, v_external_address, v_platform_prefix, v_token_symbol, v_token_title, v_creator_address, v_affiliate_address;

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
        WHEN v_platform_prefix IN ('e', 'v') THEN
            v_token_type := 'comment';
        ELSE
            RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address;
            RETURN;
        END CASE;

    IF v_token_type IS NULL THEN
        RAISE WARNING 'Failed to determine token type for %, skipping token creation', v_external_address;
        RETURN;
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] BondedTokenCreated: Executing MERGE | token=% | platform=% | type=% | total_supply=%',
        v_token_address, v_platform, v_token_type, v_total_supply;

    v_function_selector := substring(REPLACE(p_tx_input, '0x', '') from 1 for 8);
    if v_function_selector != handleops_selector then -- dfns handleOps it comes with from
        RAISE NOTICE '[EVENT_PROCESSOR] BondedTokenCreated: non-handleOps: % | Zeroing fee sponsor address',
            v_function_selector;
        p_fee_sponsor_address = NULL;
    end if;
    MERGE INTO tokens AS t
    USING (
        SELECT
            p_block_timestamp AS created_at,
            p_block_timestamp AS updated_at,
            v_token_address   AS contract_address,
            v_external_address AS external_address,
            v_platform        AS platform,
            v_affiliate_address AS affiliate_bsc_address,
            v_token_symbol    AS ticker,
            v_token_title     AS title,
            v_total_supply    AS total_supply,
            v_creator_address AS content_author_id,
            v_token_type      AS type,
            p_fee_sponsor_address AS fee_sponsor,
            p_log_index       AS log_index
    ) AS s
    ON (t.external_address = s.external_address)
    WHEN MATCHED AND t.contract_address IS NULL THEN
        UPDATE SET
            updated_at = s.updated_at,
            contract_address = s.contract_address,
            total_supply = s.total_supply,
            platform = s.platform,
            ticker = s.ticker,
            title = s.title,
            log_index = s.log_index,
            affiliate_bsc_address = COALESCE(t.affiliate_bsc_address, s.affiliate_bsc_address),
            content_author_id = COALESCE(t.content_author_id, s.content_author_id),
            fee_sponsor = s.fee_sponsor
    WHEN MATCHED AND t.contract_address IS NOT NULL THEN
        DO NOTHING
    WHEN NOT MATCHED THEN
        INSERT (
            created_at, updated_at, contract_address, external_address, platform, affiliate_bsc_address,
            ticker, title, total_supply, content_author_id, type, log_index, fee_sponsor
        )
        VALUES (
            s.created_at, s.updated_at, s.contract_address, s.external_address, s.platform, s.affiliate_bsc_address,
            s.ticker, s.title, s.total_supply, s.content_author_id, s.type, s.log_index, s.fee_sponsor
        );

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[EVENT_PROCESSOR][ELAPSED] BondedTokenCreated: Successfully processed token=% | external=% | elapsed_ms=%',
        v_token_address, v_external_address, ROUND(v_elapsed_ms, 2);
END;
$$ LANGUAGE plpgsql;

-- Fallback owner lookup via content_author_id for comments
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
    p_fee NUMERIC DEFAULT 0
) RETURNS VOID AS $$
DECLARE
    v_user_external_address TEXT;
    v_market_cap_usd usd_amount;
    v_market_cap_ion NUMERIC;
    v_owner_external_address TEXT;
    v_owner_avatar TEXT;
    v_owner_username TEXT;
    v_owner_display_name TEXT;
    v_platform TEXT;
BEGIN
    SELECT u.master_pubkey INTO v_user_external_address
    FROM user_bsc_addresses uba
    JOIN users u ON u.id = uba.user_id
    WHERE uba.bsc_address = LOWER(p_user_blockchain_address);

    IF v_user_external_address IS NULL AND LOWER(p_user_blockchain_address) = LOWER(p_token_address) THEN
        v_user_external_address := p_token_external_address;
    END IF;

    v_market_cap_ion := (p_total_supply / 1e18) * p_price_usd / p_ion_price_usd;
    v_market_cap_usd := (p_total_supply / 1e18) * p_price_usd;

    IF POSITION(':' IN p_token_external_address) > 0 THEN
        v_owner_external_address := SPLIT_PART(p_token_external_address, ':', 2);
    ELSE
        v_owner_external_address := p_token_external_address;
    END IF;

    SELECT avatar, username, display_name, platform_group
    INTO v_owner_avatar, v_owner_username, v_owner_display_name, v_platform
    FROM users
    WHERE master_pubkey = v_owner_external_address;

    -- Fallback for comments or tokens without parseable master_pubkey
    IF v_owner_username IS NULL THEN
        SELECT u.avatar, u.username, u.display_name, u.platform_group
        INTO v_owner_avatar, v_owner_username, v_owner_display_name, v_platform
        FROM tokens tok
        JOIN user_bsc_addresses uba ON uba.bsc_address = tok.content_author_id
        JOIN users u ON u.id = uba.user_id
        WHERE tok.contract_address = p_token_address
        LIMIT 1;
    END IF;

    UPDATE tokens t
    SET price_usd = p_price_usd,
        market_cap_usd = v_market_cap_usd,
        market_cap = v_market_cap_ion,
        updated_at = p_block_timestamp,
        image_url = CASE
            WHEN t.image_url IS NULL AND v_platform = 'ionconnect' AND v_owner_avatar IS NOT NULL and t.type = 'profile' THEN
                v_owner_avatar
            WHEN t.image_url IS NULL THEN
                (SELECT picture_url FROM user_tokens_suggestions WHERE content_id = t.external_address LIMIT 1)
            ELSE
                t.image_url
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

    IF p_direction = false THEN
        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, total_invested_usd, total_realized_usd, total_fees_usd, updated_at
        )
        VALUES (
            p_user_blockchain_address, p_token_address, p_token_external_address,
            v_user_external_address,
            0, 0, 0, 0, p_block_timestamp
        )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
            updated_at = EXCLUDED.updated_at,
            user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    END IF;
END; $$ LANGUAGE plpgsql;
