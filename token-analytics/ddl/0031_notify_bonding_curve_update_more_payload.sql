-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION notify_bonding_curve_update() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    payload := json_build_object(
            'external_address', NEW.external_address,
            'type', NEW.type,
            'bonding_curve_migrated', COALESCE(NEW.bonding_curve_migrated, false),
            'bonding_curve_current_amount', COALESCE(NEW.bonding_curve_current_amount::text, '0'),
            'bonding_curve_goal_amount', COALESCE(NEW.bonding_curve_goal_amount::text, '0'),
            'bonding_curve_raised_amount', COALESCE(NEW.bonding_curve_raised_amount::text, '0'),
            'bonding_curve_current_amount_usd', COALESCE(NEW.bonding_curve_current_amount_usd, 0),
            'bonding_curve_goal_amount_usd', COALESCE(NEW.bonding_curve_goal_amount_usd, 0),
            'liquidity_usd', COALESCE(NEW.liquidity_usd, 0),
            'start_price', COALESCE(NEW.start_price::text, '0'),
            'end_price', COALESCE(NEW.end_price::text, '0'),
            'total_supply', COALESCE(NEW.total_supply::text, '0'),
            'price_model', COALESCE(NEW.price_model, ''),
            'base_token', COALESCE(NEW.base_token, ''),
            'fee_sponsor_address', NEW.fee_sponsor_address,
            'updated_at', EXTRACT(EPOCH FROM NEW.updated_at)::bigint
        );

    PERFORM pg_notify('token_bonding_curve_updates', payload::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS token_bonding_curve_update_trigger ON tokens;

CREATE TRIGGER token_bonding_curve_update_trigger
    AFTER UPDATE OF bonding_curve_current_amount, bonding_curve_goal_amount,
        bonding_curve_raised_amount, bonding_curve_current_amount_usd,
        bonding_curve_goal_amount_usd, bonding_curve_migrated, liquidity_usd, start_price, end_price ON tokens
    FOR EACH ROW
    WHEN (
        OLD.bonding_curve_current_amount IS DISTINCT FROM NEW.bonding_curve_current_amount OR
        OLD.bonding_curve_goal_amount IS DISTINCT FROM NEW.bonding_curve_goal_amount OR
        OLD.bonding_curve_raised_amount IS DISTINCT FROM NEW.bonding_curve_raised_amount OR
        OLD.bonding_curve_current_amount_usd IS DISTINCT FROM NEW.bonding_curve_current_amount_usd OR
        OLD.bonding_curve_goal_amount_usd IS DISTINCT FROM NEW.bonding_curve_goal_amount_usd OR
        OLD.bonding_curve_migrated IS DISTINCT FROM NEW.bonding_curve_migrated OR
        OLD.liquidity_usd IS DISTINCT FROM NEW.liquidity_usd OR
        OLD.start_price IS DISTINCT FROM NEW.start_price OR
        OLD.end_price IS DISTINCT FROM NEW.end_price
        )
EXECUTE FUNCTION notify_bonding_curve_update();

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS fee_sponsor_address TEXT;

UPDATE tokens SET fee_sponsor_address = '0x24c7ef0f468840620e13174e44f0cf10abba3425'
WHERE platform = 'ionconnect' AND fee_sponsor_address IS NULL;

DROP FUNCTION IF EXISTS process_bonded_token_created(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP,
    p_log_index BIGINT
);

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
BEGIN
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
            p_fee_sponsor_address AS fee_sponsor_address,
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
                   log_index = COALESCE(s.log_index, t.log_index),
                   fee_sponsor_address = s.fee_sponsor_address
    WHEN MATCHED AND t.external_address = s.external_address THEN
        DO NOTHING
    WHEN NOT MATCHED THEN
        INSERT (
            created_at, updated_at, contract_address, external_address, platform, affiliate_bsc_address,
            ticker, title, total_supply, content_author_id, type, log_index, fee_sponsor_address
        )
        VALUES (
                   s.created_at, s.updated_at, s.contract_address, s.external_address, s.platform, s.affiliate_bsc_address,
                   s.ticker, s.title, s.total_supply, s.content_author_id, s.type, s.log_index, s.fee_sponsor_address
               );

    RAISE NOTICE '[EVENT_PROCESSOR] BondedTokenCreated: Successfully processed token=% | external=%', v_token_address, v_external_address;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION process_tx_log_event()
    RETURNS TRIGGER AS $$
DECLARE
    v_block_timestamp TIMESTAMP;
    v_tx_input TEXT;
    v_from TEXT;
BEGIN
    SELECT block_timestamp, input, from_address INTO v_block_timestamp, v_tx_input, v_from
    FROM transactions
    WHERE transaction_hash = NEW.transaction_hash;

    CASE NEW.topic0
        WHEN '0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd' THEN -- BondingTokenCreated
        PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_tx_input, v_from, v_block_timestamp, NEW.log_index);
        WHEN '0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c' THEN -- PairRegistered
        PERFORM process_pair_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81' THEN -- Swapped
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
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;