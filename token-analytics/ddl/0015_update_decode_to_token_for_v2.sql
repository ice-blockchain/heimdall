-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION get_platform_group(p_prefix TEXT)
RETURNS platform_type AS $$
BEGIN
    IF p_prefix IN ('z','y','x','w') THEN
        RETURN 'xcom'::platform_type;
    ELSIF p_prefix IN ('a','b','c','d') THEN
        RETURN 'ionconnect'::platform_type;
    ELSE
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION decode_to_token_from_input(tx_input TEXT)
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    swap_calldata TEXT;
    to_token_offset_bytes INT;
    to_token_length_bytes INT;
    to_token_hex TEXT;
    data_start_pos INT;
    
    version INT;
    records_count INT;
    presence_mask INT;
    name_len INT;
    symbol_len INT;
    ext_addr_len INT;
    token_mask INT;
    hex_offset INT;
    external_address_hex TEXT;
    result TEXT;
BEGIN
    -- First, extract swap calldata (handles both direct swap and custom handleOps)
    swap_calldata := extract_swap_calldata_from_custom_handleops(tx_input);
    
    hex_clean := REPLACE(swap_calldata, '0x', '');
    hex_clean := substring(hex_clean from 9); -- Skip first 8 hex chars (4 bytes = function signature)

    -- toToken is parameter index 1 (second parameter, after baseToken at index 0)
    to_token_offset_bytes := decode_uint256('0x' || hex_clean, 1)::INT;
    IF to_token_offset_bytes = 0 THEN
        RETURN '';
    END IF;

    to_token_length_bytes := decode_uint256('0x' || hex_clean, to_token_offset_bytes / 32)::INT;
    IF to_token_length_bytes = 0 THEN
        RETURN '';
    END IF;

    -- Extract toToken hex data (starts 32 bytes after the length word)
    data_start_pos := (to_token_offset_bytes + 32) * 2 + 1;
    to_token_hex := substring(hex_clean from data_start_pos for (to_token_length_bytes * 2));

    -- Thin address check (subsequent swap): 20 bytes = 40 hex chars
    IF length(to_token_hex) <= 40 THEN
        RETURN '';
    END IF;

    -- Parse V2 Fat Address
    -- Global Header (4 bytes = 8 hex chars): [version][recordsCount][presenceMask(2 bytes)]
    version := ('x' || substring(to_token_hex from 1 for 2))::bit(8)::int;
    IF version != 2 THEN
        RAISE WARNING 'Unsupported fat address version: %', version;
        RETURN '';
    END IF;

    records_count := ('x' || substring(to_token_hex from 3 for 2))::bit(8)::int;
    presence_mask := ('x' || substring(to_token_hex from 5 for 4))::bit(16)::int;

    hex_offset := 9; -- Start after global header (4 bytes = 8 hex + 1 for 1-based index)

    -- FIRST token record header (8 bytes = 16 hex chars)
    -- [nameLen][symbolLen][extAddrLen][extType][tokenMask(4 bytes)]
    name_len := ('x' || substring(to_token_hex from hex_offset for 2))::bit(8)::int;
    symbol_len := ('x' || substring(to_token_hex from hex_offset+2 for 2))::bit(8)::int;
    ext_addr_len := ('x' || substring(to_token_hex from hex_offset+4 for 2))::bit(8)::int;
    -- externalType at hex_offset+6 (not used)
    token_mask := ('x' || substring(to_token_hex from hex_offset+8 for 8))::bit(32)::int;
    hex_offset := hex_offset + 16;

    -- Skip mandatory bonding address (20 bytes = 40 hex chars)
    hex_offset := hex_offset + 40;

    -- Skip optional bonding prices (2 x uint256 = 64 bytes = 128 hex chars) if bit 0x02 is set
    IF (token_mask & 2) != 0 THEN
        hex_offset := hex_offset + 128;
    END IF;

    -- Skip optional bonding supply (1 x uint256 = 32 bytes = 64 hex chars) if bit 0x04 is set
    IF (token_mask & 4) != 0 THEN
        hex_offset := hex_offset + 64;
    END IF;

    -- Skip name and symbol strings
    hex_offset := hex_offset + (name_len * 2) + (symbol_len * 2);

    -- Extract externalAddress string
    external_address_hex := substring(to_token_hex from hex_offset for (ext_addr_len * 2));
    result := rtrim(convert_from(decode(external_address_hex, 'hex'), 'UTF8'), E'\\0');

    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        RAISE WARNING 'decode_to_token_from_input failed: %', SQLERRM;
        RETURN '';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

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

    INSERT INTO tokens (
        created_at, updated_at, contract_address, external_address, platform, affiliate_bsc_address,
        ticker, title, total_supply, content_author_id, type, log_index
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
        p_log_index
    )
    ON CONFLICT (contract_address) DO UPDATE SET
        updated_at = EXCLUDED.updated_at,
        external_address = EXCLUDED.external_address,
        total_supply = EXCLUDED.total_supply,
        platform = EXCLUDED.platform,
        ticker = COALESCE(EXCLUDED.ticker, tokens.ticker),
        title = COALESCE(EXCLUDED.title, tokens.title),
        affiliate_bsc_address = COALESCE(EXCLUDED.affiliate_bsc_address, tokens.affiliate_bsc_address),
        content_author_id = COALESCE(EXCLUDED.content_author_id, tokens.content_author_id),
        type = COALESCE(EXCLUDED.type, tokens.type),
        log_index = COALESCE(EXCLUDED.log_index, tokens.log_index);

    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION parse_custom_handleops(tx_input TEXT)
RETURNS JSONB AS $$
DECLARE
    hex_clean TEXT;
    function_selector TEXT;
    handleops_selector TEXT := '74fa4121';
    userops_offset_hex TEXT;
    userops_offset_int INT;
    userops_start_pos INT;
    userops_length_hex TEXT;
    userops_length_int INT;
    userops_data_start INT;
    sender_hex TEXT;
    sender_addr TEXT;
    nonce_hex TEXT;
    calldata_length_hex TEXT;
    calldata_length_int INT;
    calldata_start INT;
    calldata_hex TEXT;
    calldata_full TEXT;
    r_hex TEXT;
    vs_hex TEXT;
BEGIN
    IF tx_input IS NULL OR length(tx_input) < 10 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false);
    END IF;

    hex_clean := REPLACE(tx_input, '0x', '');
    function_selector := substring(hex_clean from 1 for 8);
    
    IF function_selector != handleops_selector THEN
        RETURN jsonb_build_object('isCustomHandleOps', false);
    END IF;
    
    -- Verify minimum length (selector + 3 params = 8 + 64*3 = 200 hex chars minimum)
    IF length(hex_clean) < 200 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', 'input too short');
    END IF;
    
    -- Parse userOps offset (should be 0x60 = 96 bytes)
    -- Use direct hex conversion for small values to avoid integer overflow
    userops_offset_hex := substring(hex_clean from 9 for 64);
    userops_offset_int := ('x' || substring(userops_offset_hex from 57 for 8))::bit(32)::int;
    
    -- Parse r and vs (signature components)
    r_hex := '0x' || substring(hex_clean from 73 for 64);
    vs_hex := '0x' || substring(hex_clean from 137 for 64);
    
    -- Calculate userOps start position in hex chars (offset * 2 + 1 for 1-based indexing)
    userops_start_pos := userops_offset_int * 2 + 1;
    
    IF length(hex_clean) < userops_start_pos + 64 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', 'userOps offset out of bounds');
    END IF;
    
    userops_length_hex := substring(hex_clean from userops_start_pos for 64);
    -- Use direct hex conversion for small values to avoid integer overflow
    userops_length_int := ('x' || substring(userops_length_hex from 57 for 8))::bit(32)::int;
    
    -- UserOps data starts after length field
    userops_data_start := userops_start_pos + 64;
    
    IF length(hex_clean) < userops_data_start + userops_length_int * 2 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', 'userOps data truncated');
    END IF;
    
    -- Parse UserOps structure:
    -- [0:40]   - sender (20 bytes)
    -- [40:104] - nonce (32 bytes)
    -- [104:168] - callDataLength (32 bytes)
    -- [168:...] - callData
    
    IF userops_length_int * 2 < 168 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', 'userOps data too short');
    END IF;
    
    -- Extract sender (20 bytes)
    sender_hex := substring(hex_clean from userops_data_start for 40);
    sender_addr := '0x' || LOWER(sender_hex);
    
    -- Extract nonce (32 bytes)
    nonce_hex := '0x' || substring(hex_clean from (userops_data_start + 40) for 64);
    
    -- Extract callData length (32 bytes)
    -- Use direct hex conversion for small values to avoid integer overflow
    calldata_length_hex := substring(hex_clean from (userops_data_start + 104) for 64);
    calldata_length_int := ('x' || substring(calldata_length_hex from 57 for 8))::bit(32)::int;
    
    -- Extract callData
    calldata_start := userops_data_start + 168;
    IF length(hex_clean) < calldata_start + calldata_length_int * 2 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', 'callData truncated');
    END IF;
    
    calldata_hex := substring(hex_clean from calldata_start for (calldata_length_int * 2));
    calldata_full := '0x' || calldata_hex;
    
    RETURN jsonb_build_object(
        'isCustomHandleOps', true,
        'sender', sender_addr,
        'nonce', nonce_hex,
        'callData', calldata_full,
        'r', r_hex,
        'vs', vs_hex
    );
EXCEPTION
    WHEN OTHERS THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', SQLERRM);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

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
    -- Event includes feeToken at index 1:
    -- Word 0: direction, Word 1: feeToken, Word 2: inputAmount, Word 3: outputAmount, Word 4: fee
    v_input_amount := decode_uint256(p_data, 2);
    v_output_amount := decode_uint256(p_data, 3);
    v_fee := decode_uint256(p_data, 4);

    BEGIN
        v_token_external_address := decode_to_token_from_input(p_tx_input);
        v_base_token := decode_base_token_from_input(p_tx_input);
    EXCEPTION WHEN OTHERS THEN
        v_token_external_address := NULL;
        v_base_token := NULL;
    END;

    IF v_token_external_address IS NOT NULL AND length(v_token_external_address) > 0 THEN
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
        IF v_base_price_usd IS NULL OR v_base_price_usd = 0 THEN
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

CREATE OR REPLACE FUNCTION process_tx_log_event()
RETURNS TRIGGER AS $$
DECLARE
    v_block_timestamp TIMESTAMP;
    v_tx_input TEXT;
BEGIN
    SELECT block_timestamp, input INTO v_block_timestamp, v_tx_input
    FROM transactions
    WHERE transaction_hash = NEW.transaction_hash;

    CASE NEW.topic0
        WHEN '0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd' THEN -- BondingTokenCreated
            PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_block_timestamp, NEW.log_index);
        WHEN '0x872521cd21d976cd52c101bb81804e331c479f7895644ae16140b559222fda5c' THEN -- PairRegistered
            PERFORM process_pair_registered(NEW.topics, v_block_timestamp);
        WHEN '0x163f655f7f84a04389233837ff842844953ef4efba74f5d9317d37131b3a6a81' THEN -- Swapped
            PERFORM process_swapped(NEW.transaction_hash, NEW.topics, NEW.data, v_tx_input, v_block_timestamp, NEW.log_index, NEW.address);
        WHEN '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118' THEN -- PoolCreated (uniswap)
            PERFORM process_pool_registered(NEW.topics, NEW.data, v_block_timestamp);
        WHEN '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67' THEN -- Swap (uniswap)
            PERFORM process_swapped_uniswap(NEW.transaction_hash, NEW.topics, NEW.data, v_block_timestamp, NEW.log_index, NEW.address);
        ELSE
            NULL;
        END CASE;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

