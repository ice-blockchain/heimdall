ALTER TABLE tokens ADD COLUMN IF NOT EXISTS affiliate_bsc_address TEXT;


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
    v_token_title TEXT;
    v_creator_token_address TEXT; --for content tokens
    v_creator_address TEXT;
    v_affiliate_address TEXT;
BEGIN
    IF array_length(p_topics, 1) < 2 THEN
        RETURN;
    END IF;

    v_token_address := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_token_title := decode_string_abi(p_data, 0); -- name
    v_token_symbol := decode_string_abi(p_data, 1); -- symbol
    v_creator_token_address := LOWER('0x' || substring(p_data from (2*64+27) for 40)); -- index 2
    v_platform_prefix := CHR(decode_uint256(p_data, 3)::INT); -- index 3
    v_external_address := decode_string_abi(p_data, 4);
    v_creator_address := LOWER('0x' || substring(p_data from (5*64+27) for 40));
    v_affiliate_address := LOWER('0x' || substring(p_data from (6*64+27) for 40));
    v_total_supply := decode_uint256(p_data, 7);


    IF v_external_address IS NULL OR v_external_address  = '' THEN
        RAISE WARNING 'Empty external address, skipping token creation';
        RETURN;
    END IF;

    v_platform := get_platform_group(v_platform_prefix);

    IF v_platform IS NULL THEN
        RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address_raw;
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
            RAISE WARNING 'Invalid external address format (unknown prefix ''%''): %, skipping token creation', v_platform_prefix, v_external_address_raw;
            RETURN;
        END CASE;

    -- For ALL tokens, content_author_id will be populated from first Swapped event
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
               NULL, -- Will be filled on first swap
               v_token_type,
               v_creator_address,
               p_log_index
           )
    ON CONFLICT (external_address) DO UPDATE SET
                                                 updated_at = EXCLUDED.updated_at,
                                                 total_supply = EXCLUDED.total_supply,
                                                 contract_address = EXCLUDED.contract_address,
                                                 bnb_bsc_metadata_owner_address = EXCLUDED.bnb_bsc_metadata_owner_address,
                                                 platform = EXCLUDED.platform,
                                                 ticker = COALESCE(EXCLUDED.ticker, tokens.ticker),
                                                 title = COALESCE(EXCLUDED.title, tokens.title),
                                                 log_index = COALESCE(EXCLUDED.log_index, tokens.log_index);

    RAISE DEBUG 'TokenCreated processed: token=%', v_token_address;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION decode_to_token_from_input(tx_input TEXT)
    RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    to_token_offset_bytes INT;
    to_token_length_bytes INT;
    v_symbol_len INT;
    v_name_len INT;
    ext_length INT;
    v_ext_offset INT;
    to_token_hex TEXT;
    data_start_pos INT;
    external_address TEXT;
    result TEXT;
BEGIN
    hex_clean := REPLACE(tx_input, '0x', '');
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
    raise warning 'external_address: %', external_address;
    ext_length := char_length(external_address);
    if ext_length <= 64 THEN
        -- For 1+ swaps: toToken is just 20-byte contract address, no external_address
        -- Return empty string so trigger will use pair_id lookup
        RETURN '';
    END IF;
    -- 1st byte
    v_symbol_len := ('0x' || substring(external_address for 2))::bit(8)::int;
    -- 2nd byte
    v_name_len := ('0x' || substring(external_address from 3 for 2))::bit(8)::int;

    -- Header is 32 bytes (64 hex chars).
    -- Offset = (32 + symbolLen + nameLen) * 2 + 1
    v_ext_offset := (32 + v_symbol_len + v_name_len) * 2 + 1;

    external_address := substring(external_address from v_ext_offset);
    result := rtrim(convert_from(decode(external_address, 'hex'), 'UTF8'), E'\\0');

    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        RETURN '';
END;
$$ LANGUAGE plpgsql IMMUTABLE;


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
        WHEN '0xf1aad4192131f14ec094f5319421d9274539312c962d0ce8121ba86f52f25db0' THEN -- BondedTokenCreated
        PERFORM process_bonded_token_created(NEW.topics, NEW.data, v_block_timestamp, NEW.log_index);
        WHEN '0x157b5bda8c36b5ae40a6f0d041dce8790309b04707aa024e9a73ee87287372b4' THEN -- PairRegistered
        PERFORM process_pair_registered(NEW.topics, v_block_timestamp);
        WHEN '0xe4a3738af8db2ebbadd5b857bb8d2e0e6650fade69486571ff038a2a81433ca0' THEN -- Swapped
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

