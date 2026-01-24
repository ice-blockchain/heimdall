-- SPDX-License-Identifier: ice License 1.0

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
    v_platform_prefix := CHR(decode_uint256(p_data, 2)::INT); -- externalType
    v_external_address := decode_string_abi(p_data, 3); -- externalAddress
    v_total_supply := decode_uint256(p_data, 4); -- totalSupply
    v_creator_address := LOWER('0x' || substring(p_data from (5*64+27) for 40)); -- creatorAddress
    v_affiliate_address := LOWER('0x' || substring(p_data from (6*64+27) for 40)); -- affiliateAddress

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
            p_log_index       AS log_index
    ) AS s
    ON (t.contract_address = s.contract_address OR t.external_address = s.external_address)
    WHEN MATCHED AND t.contract_address = s.contract_address THEN
        UPDATE SET
                   updated_at = s.updated_at,
                   external_address = s.external_address,
                   total_supply = s.total_supply,
                   platform = s.platform,
                   ticker = COALESCE(s.ticker, t.ticker),
                   title = COALESCE(s.title, t.title),
                   affiliate_bsc_address = COALESCE(s.affiliate_bsc_address, t.affiliate_bsc_address),
                   content_author_id = COALESCE(s.content_author_id, t.content_author_id),
                   type = COALESCE(s.type, t.type),
                   log_index = COALESCE(s.log_index, t.log_index)
    WHEN MATCHED AND t.external_address = s.external_address THEN
        DO NOTHING
    WHEN NOT MATCHED THEN
        INSERT (
            created_at, updated_at, contract_address, external_address, platform, affiliate_bsc_address,
            ticker, title, total_supply, content_author_id, type, log_index
        )
        VALUES (
                   s.created_at, s.updated_at, s.contract_address, s.external_address, s.platform, s.affiliate_bsc_address,
                   s.ticker, s.title, s.total_supply, s.content_author_id, s.type, s.log_index
               );

    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
END;
$$ LANGUAGE plpgsql;