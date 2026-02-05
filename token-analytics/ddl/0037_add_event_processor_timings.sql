-- SPDX-License-Identifier: ice License 1.0

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

CREATE OR REPLACE FUNCTION process_pair_registered(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_base_token TEXT;
    v_pair_id TEXT;
    v_other_token TEXT;
    v_price_model TEXT;
    v_start_price NUMERIC;
    v_end_price NUMERIC;
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    IF array_length(p_topics, 1) < 4 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Invalid topics array length: %', array_length(p_topics, 1);
        RETURN;
    END IF;

    v_pair_id := LOWER(p_topics[2]);
    v_base_token := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_other_token := LOWER('0x' || substring(p_topics[4] from 27 for 40));
    
    v_price_model := LOWER('0x' || substring(p_data from 27 for 40)); -- priceModel at offset 0
    v_start_price := decode_uint256(p_data, 1); -- startPrice at offset 1
    v_end_price := decode_uint256(p_data, 2); -- endPrice at offset 2

    RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Processing token=% | pair_id=% | base_token=% | price_model=% | start_price=% | end_price=%',
        v_other_token, v_pair_id, v_base_token, v_price_model, v_start_price, v_end_price;
    
    UPDATE tokens
    SET
        base_token = v_base_token,
        pair_id = v_pair_id,
        price_model = v_price_model,
        start_price = v_start_price,
        end_price = v_end_price,
        updated_at = p_block_timestamp
    WHERE LOWER(contract_address) = v_other_token;

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[EVENT_PROCESSOR][ELAPSED] PairRegistered: Successfully processed token=% | pair_id=% | elapsed_ms=%',
        v_other_token, v_pair_id, ROUND(v_elapsed_ms, 2);
END;
$$ LANGUAGE plpgsql;

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
    v_burned NUMERIC;
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    IF array_length(p_topics, 1) < 3 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Invalid topics array length: % | tx=%', array_length(p_topics, 1), p_transaction_hash;
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_pair_id := LOWER(p_topics[3]);
    v_direction := (decode_uint256(p_data, 0) != 0);
    -- Event includes feeToken at index 1:
    -- Word 0: direction, Word 1: feeToken, Word 2: inputAmount, Word 3: outputAmount, Word 4: fee
    v_input_amount := decode_uint256(p_data, 2);
    v_output_amount := decode_uint256(p_data, 3);
    v_fee := decode_uint256(p_data, 4);

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
        v_price_usd := (v_input_amount / v_output_amount) * v_base_price_usd;
    ELSE -- sell
        v_price_usd := (v_output_amount / v_input_amount) * v_base_price_usd;
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
    PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                           v_direction, v_input_amount, v_output_amount, v_price_usd, v_base_price_usd, v_total_supply);

    IF v_token_type = 'profile' THEN
        PERFORM update_base_token_price(v_token_address, v_token_ticker, v_price_usd);
    END IF;

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[EVENT_PROCESSOR][ELAPSED] Swapped: Successfully processed | tx=% | token=% | user=% | external=% | elapsed_ms=%',
        p_transaction_hash, v_token_address, v_user_address, v_token_external_address, ROUND(v_elapsed_ms, 2);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_pool_registered(
    p_topics TEXT[],
    p_data     TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_token0 TEXT;
    v_pool_address TEXT;
    v_token1 TEXT;
    v_fee SMALLINT;
    v_token_address TEXT;
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    IF array_length(p_topics, 1) < 4 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] PoolRegistered: Invalid topics array length: %', array_length(p_topics, 1);
        RETURN;
    END IF;

    v_token0 := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_token1 := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_fee := p_topics[4]::BIGINT;
    v_pool_address := LOWER('0x' || substring(p_data from (64+27))); -- 64 is hex abi offset (2nd) + 27 prefix to trim 20 bytes of addr

    RAISE NOTICE '[EVENT_PROCESSOR] PoolRegistered: Processing pool=% | token0=% | token1=% | fee=%',
        v_pool_address, v_token0, v_token1, v_fee;

    IF v_pool_address IS NULL OR v_pool_address = '' THEN
        RAISE EXCEPTION 'Failed to decode pool address % %', v_token0, v_token1;
        RETURN;
    END IF;

    SELECT tokens.contract_address from tokens WHERE
        (LOWER(contract_address) = LOWER(v_token0) and base_token = v_token1) OR
        (LOWER(contract_address) = LOWER(v_token1) and base_token = v_token0) LIMIT 1 -- only one, creator token cannot be bought with content tokens
    INTO v_token_address;

    IF v_token_address IS NULL OR v_token_address = '' THEN
        RAISE WARNING 'Failed to get token for tokens pool % %', v_token0, v_token1;
        RETURN;
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] PoolRegistered: Found token=% for pool=%', v_token_address, v_pool_address;

    INSERT INTO uniswap_pools(pool_address, token_address, token0, token1, fee, created_at)
    VALUES (v_pool_address,v_token_address, v_token0, v_token1, v_fee, p_block_timestamp) ON CONFLICT DO NOTHING;

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[EVENT_PROCESSOR][ELAPSED] PoolRegistered: Successfully processed | pool=% | token=% | elapsed_ms=%',
        v_pool_address, v_token_address, ROUND(v_elapsed_ms, 2);
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
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    IF array_length(p_topics, 1) < 3 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Uniswap Swap: Invalid topics array length: % | tx=% | pool=%',
            array_length(p_topics, 1), p_transaction_hash, p_address;
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_input_amount0 := to_int256(decode_uint256(p_data, 0));
    v_input_amount1 := to_int256(decode_uint256(p_data, 1));

    RAISE NOTICE '[EVENT_PROCESSOR] Uniswap Swap: Processing | tx=% | pool=% | swapper=% | recipient=% | amount0=% | amount1=%',
        p_transaction_hash, p_address, v_swapper, v_recipient, v_input_amount0, v_input_amount1;

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

    RAISE NOTICE '[EVENT_PROCESSOR] Uniswap Swap: Found token | tx=% | pool=% | token=% | external=% | base_token=% | base_price_usd=% | token0_is_tc=%',
        p_transaction_hash, p_address, v_token_address, v_token_external_address, v_base_token, v_base_price_usd, v_token0_is_tc_token;

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

    RAISE NOTICE '[EVENT_PROCESSOR] Uniswap Swap: Calculated amounts | tx=% | token=% | input=% | output=% | direction=%',
        p_transaction_hash, v_token_address, v_input_amount, v_output_amount, v_direction;

    IF v_direction = false THEN -- buy
        v_user_address := v_recipient;
        v_price_usd := (v_input_amount / v_output_amount) * v_base_price_usd;
    ELSE -- sell
        v_user_address = v_swapper;
        v_price_usd := (v_output_amount / v_input_amount) * v_base_price_usd;
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] Uniswap Swap: Calculated price | tx=% | token=% | price_usd=% | user=%',
        p_transaction_hash, v_token_address, v_price_usd, v_user_address;

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
    
    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[EVENT_PROCESSOR][ELAPSED] Uniswap Swap: Successfully processed | tx=% | pool=% | token=% | user=% | external=% | elapsed_ms=%',
        p_transaction_hash, p_address, v_token_address, v_user_address, v_token_external_address, ROUND(v_elapsed_ms, 2);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION process_tx_log_event()
    RETURNS TRIGGER AS $$
DECLARE
    v_block_timestamp TIMESTAMP;
    v_tx_input TEXT;
    v_from TEXT;
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    
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
    
    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[TRIGGER][ELAPSED] process_tx_log_event: Processed log | tx=% | topic0=% | elapsed_ms=%',
        NEW.transaction_hash, NEW.topic0, ROUND(v_elapsed_ms, 2);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trigger_move_incoming_logs()
    RETURNS TRIGGER AS $$
DECLARE
    v_start_time TIMESTAMP;
    v_elapsed_ms NUMERIC;
    v_tx_count INTEGER;
    v_log_count INTEGER;
BEGIN
    v_start_time := clock_timestamp();
    
    INSERT INTO transactions (
        chain_id,
        block_number,
        transaction_hash,
        transaction_index,
        gas,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        nonce,
        block_hash,
        to_address,
        transaction_type,
        value,
        y_parity,
        input,
        from_address,
        block_timestamp
    ) SELECT
            transaction_data->>'chainId',
            (transaction_data->>'blockNumber')::BIGINT,
            transaction_data->>'hash',
            (transaction_data->>'transactionIndex')::BIGINT,
            (transaction_data->>'gas')::BIGINT,
            (transaction_data->>'gasPrice')::BIGINT,
            (transaction_data->>'maxFeePerGas')::BIGINT,
            (transaction_data->>'maxPriorityFeePerGas')::BIGINT,
            (transaction_data->>'nonce')::BIGINT,
            transaction_data->>'blockHash',
            COALESCE(transaction_data->>'to', '0x0000000000000000000000000000000000000000'),
            transaction_data->>'type',
            (transaction_data->>'value')::BIGINT,
            (transaction_data->>'yParity')::BIGINT,
            transaction_data->>'input',
            transaction_data->>'from',
            to_timestamp((transaction_data->>'blockTimestamp')::BIGINT)
         FROM jsonb_array_elements(NEW.data -> 'transactions') as transaction_data
        ON CONFLICT(transaction_hash) DO NOTHING;
    
    GET DIAGNOSTICS v_tx_count = ROW_COUNT;

    INSERT INTO tx_logs(stream_id, address, topics, topic0, data, block_number, transaction_hash, log_index, removed)
    (SELECT
              NEW.data ->> 'stream',
              log_elem->>'address' as address,
              (SELECT t.topics from jsonb_to_record(log_elem) as t (topics TEXT[])) AS topics,
              (log_elem->'topics'->>0) as topic0,
              log_elem->>'data' as data,
              (tx_data->>'blockNumber')::BIGINT as block_number,
              tx_data->>'hash' as transaction_hash,
              (log_elem->>'logIndex')::BIGINT as log_index,
              (log_elem->>'removed')::BOOLEAN as removed
              FROM jsonb_array_elements(NEW.data -> 'transactions') as tx_data,
                   jsonb_array_elements(tx_data -> 'logs') as log_elem)
    ON CONFLICT (transaction_hash, log_index) DO NOTHING;
    
    GET DIAGNOSTICS v_log_count = ROW_COUNT;
    
    DELETE FROM smart_contract_transactions WHERE to_block_number <= NEW.to_block_number;

    v_elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
    RAISE NOTICE '[TRIGGER][ELAPSED] trigger_move_incoming_logs: Processed block | to_block=% | tx_count=% | log_count=% | elapsed_ms=%',
        NEW.to_block_number, v_tx_count, v_log_count, ROUND(v_elapsed_ms, 2);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;