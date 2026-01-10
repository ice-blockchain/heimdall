-- SPDX-License-Identifier: ice License 1.0

-- Parse custom handleOps function: handleOps(bytes userOps, uint256 r, uint256 vs)
-- Structure:
-- [0:8]   - selector (0x74fa4121)
-- [8:72]  - offset to userOps (always 0x60 = 96 bytes)
-- [72:136] - r (signature part 1)
-- [136:200] - vs (signature part 2, EIP-2098 compact)
-- [200:264] - userOps length in bytes
-- [264:...] - userOps data: sender(20) + nonce(32) + callDataLength(32) + callData
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
    userops_offset_hex := substring(hex_clean from 9 for 64);
    userops_offset_int := decode_uint256('0x' || userops_offset_hex, 0)::INT;
    
    -- Parse r and vs (signature components)
    r_hex := '0x' || substring(hex_clean from 73 for 64);
    vs_hex := '0x' || substring(hex_clean from 137 for 64);
    
    -- Calculate userOps start position in hex chars (offset * 2 + 1 for 1-based indexing)
    userops_start_pos := userops_offset_int * 2 + 1;
    
    IF length(hex_clean) < userops_start_pos + 64 THEN
        RETURN jsonb_build_object('isCustomHandleOps', false, 'error', 'userOps offset out of bounds');
    END IF;
    
    userops_length_hex := substring(hex_clean from userops_start_pos for 64);
    userops_length_int := decode_uint256('0x' || userops_length_hex, 0)::INT;
    
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
    calldata_length_hex := substring(hex_clean from (userops_data_start + 104) for 64);
    calldata_length_int := decode_uint256('0x' || calldata_length_hex, 0)::INT;
    
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


CREATE OR REPLACE FUNCTION extract_swap_calldata_from_custom_handleops(tx_input TEXT)
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    function_selector TEXT;
    swap_4param_selector TEXT := '83362e17';
    swap_5param_selector TEXT := '027c101d';
    handleops_selector TEXT := '74fa4121';
    swap_position INT;
BEGIN
    IF tx_input IS NULL OR length(tx_input) < 10 THEN
        RETURN tx_input;
    END IF;

    hex_clean := REPLACE(tx_input, '0x', '');
    function_selector := substring(hex_clean from 1 for 8);

    IF function_selector != handleops_selector THEN
        RETURN tx_input;
    END IF;

    -- Search for 4-param swap selector
    swap_position := position(swap_4param_selector in hex_clean);
    IF swap_position > 0 THEN
        RETURN '0x' || substring(hex_clean from swap_position);
    END IF;

    -- Search for 5-param swap selector
    swap_position := position(swap_5param_selector in hex_clean);
    IF swap_position > 0 THEN
        RETURN '0x' || substring(hex_clean from swap_position);
    END IF;

    RETURN tx_input;
EXCEPTION
    WHEN OTHERS THEN
        RETURN tx_input;
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- Update decode_base_token_from_input to support custom handleOps transactions
CREATE OR REPLACE FUNCTION decode_base_token_from_input(tx_input TEXT)
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    swap_calldata TEXT;
    base_token_offset_bytes INT;
    base_token_length_bytes INT;
    base_token_hex TEXT;
    data_start_pos INT;
BEGIN
    -- First, extract swap calldata (handles both direct swap and custom handleOps)
    swap_calldata := extract_swap_calldata_from_custom_handleops(tx_input);
    
    hex_clean := REPLACE(swap_calldata, '0x', '');
    hex_clean := substring(hex_clean from 9); -- Skip first 8 hex chars (4 bytes = function signature)

    -- baseToken is parameter index 0 (offset to bytes data)
    base_token_offset_bytes := decode_uint256('0x' || hex_clean, 0)::INT;

    IF base_token_offset_bytes = 0 THEN
        RETURN NULL;
    END IF;

    base_token_length_bytes := decode_uint256('0x' || hex_clean, base_token_offset_bytes / 32)::INT;

    IF base_token_length_bytes = 0 OR base_token_length_bytes > 32 THEN
        RETURN NULL;
    END IF;

    data_start_pos := (base_token_offset_bytes + 32) * 2 + 1;
    base_token_hex := substring(hex_clean from data_start_pos for (base_token_length_bytes * 2));

    RETURN LOWER('0x' || base_token_hex);
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- Update decode_to_token_from_input to support custom handleOps transactions
CREATE OR REPLACE FUNCTION decode_to_token_from_input(tx_input TEXT)
RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    swap_calldata TEXT;
    to_token_offset_bytes INT;
    to_token_length_bytes INT;
    ext_length INT;
    to_token_hex TEXT;
    data_start_pos INT;
    external_address TEXT;
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
    -- first 20 bytes is content creator token, for content tokens
    external_address := to_token_hex;
    ext_length := char_length(external_address);
    if ext_length <= 40 THEN
        -- For 1+ swaps: toToken is just 20-byte contract address, no external_address
        -- Return empty string so trigger will use pair_id lookup
        RETURN '';
    END IF;
    external_address := substring(external_address from 41);
    result := rtrim(convert_from(decode(external_address, 'hex'), 'UTF8'), E'\\0');

    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        RETURN '';
END;
$$ LANGUAGE plpgsql IMMUTABLE;
