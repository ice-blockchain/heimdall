-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS user_aggregate_positions (
    user_external_address TEXT NOT NULL,
    external_address      TEXT NOT NULL,
    contract_address      TEXT NOT NULL,
    amount                uint256 NOT NULL DEFAULT 0,
    total_invested_usd    usd_amount DEFAULT 0,
    total_realized_usd    usd_amount DEFAULT 0,
    total_fees_usd        usd_amount DEFAULT 0,
    updated_at            TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_external_address, external_address)
);
CREATE INDEX IF NOT EXISTS idx_uap_external_address ON user_aggregate_positions (external_address);

ALTER TABLE user_token_positions ADD COLUMN IF NOT EXISTS total_fees_usd usd_amount DEFAULT 0;

ALTER TABLE user_aggregate_positions ADD COLUMN IF NOT EXISTS last_update_block BIGINT NOT NULL DEFAULT 0;
ALTER TABLE user_aggregate_positions ADD COLUMN IF NOT EXISTS last_update_tx_hash TEXT NOT NULL DEFAULT '';

INSERT INTO user_aggregate_positions (
    user_external_address, external_address, contract_address,
    amount, total_invested_usd, total_realized_usd, total_fees_usd, updated_at
)
SELECT
    utp.user_external_address,
    utp.external_address,
    MIN(utp.contract_address),
    SUM(utp.amount::NUMERIC)::uint256,
    SUM(COALESCE(utp.total_invested_usd, 0)),
    SUM(COALESCE(utp.total_realized_usd, 0)),
    SUM(COALESCE(utp.total_fees_usd, 0)),
    MAX(utp.updated_at)
FROM user_token_positions utp
WHERE utp.user_external_address IS NOT NULL AND utp.user_external_address != ''
GROUP BY utp.user_external_address, utp.external_address
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION update_aggregate_position()
RETURNS TRIGGER AS $$
DECLARE
    v_user_ext TEXT;
    v_user_bsc TEXT;
    v_contract TEXT;
    v_amount_delta   NUMERIC;
    v_invested_delta NUMERIC;
    v_realized_delta NUMERIC;
    v_fees_delta     NUMERIC;
BEGIN
    v_user_ext := COALESCE(NEW.user_external_address, OLD.user_external_address);
    v_user_bsc := COALESCE(NEW.user_blockchain_address, OLD.user_blockchain_address);
    v_contract := COALESCE(NEW.contract_address, OLD.contract_address);

    -- Skip if user_external_address is empty (no user identity)
    -- Exception: for content token pools, user_external_address = token's external_address
    IF v_user_ext IS NULL OR v_user_ext = '' THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_amount_delta   := NEW.amount;
        v_invested_delta := COALESCE(NEW.total_invested_usd, 0);
        v_realized_delta := COALESCE(NEW.total_realized_usd, 0);
        v_fees_delta     := COALESCE(NEW.total_fees_usd, 0);
    ELSIF TG_OP = 'UPDATE' THEN
        v_amount_delta   := NEW.amount - OLD.amount;
        v_invested_delta := COALESCE(NEW.total_invested_usd, 0) - COALESCE(OLD.total_invested_usd, 0);
        v_realized_delta := COALESCE(NEW.total_realized_usd, 0) - COALESCE(OLD.total_realized_usd, 0);
        v_fees_delta     := COALESCE(NEW.total_fees_usd, 0) - COALESCE(OLD.total_fees_usd, 0);
    END IF;

    -- Skip no-op updates
    IF v_amount_delta = 0 AND v_invested_delta = 0 AND v_realized_delta = 0 AND v_fees_delta = 0 THEN
        RETURN NEW;
    END IF;

    INSERT INTO user_aggregate_positions (
        user_external_address, external_address, contract_address,
        amount, total_invested_usd, total_realized_usd, total_fees_usd, updated_at,
        last_update_block, last_update_tx_hash
    ) VALUES (
        v_user_ext, NEW.external_address, NEW.contract_address,
        GREATEST(v_amount_delta, 0)::uint256, GREATEST(v_invested_delta, 0), GREATEST(v_realized_delta, 0), GREATEST(v_fees_delta, 0), NOW(),
        COALESCE(NEW.last_update_block, 0), COALESCE(NEW.last_update_tx_hash, '')
    )
    ON CONFLICT (user_external_address, external_address) DO UPDATE SET
        amount             = GREATEST(user_aggregate_positions.amount::NUMERIC + v_amount_delta, 0)::uint256,
        total_invested_usd = GREATEST(user_aggregate_positions.total_invested_usd + v_invested_delta, 0),
        total_realized_usd = GREATEST(user_aggregate_positions.total_realized_usd + v_realized_delta, 0),
        total_fees_usd     = GREATEST(user_aggregate_positions.total_fees_usd + v_fees_delta, 0),
        contract_address   = EXCLUDED.contract_address,
        updated_at         = NOW(),
        last_update_block  = CASE WHEN EXCLUDED.last_update_block > user_aggregate_positions.last_update_block 
                                  THEN EXCLUDED.last_update_block 
                                  ELSE user_aggregate_positions.last_update_block END,
        last_update_tx_hash = CASE WHEN EXCLUDED.last_update_block > user_aggregate_positions.last_update_block 
                                   THEN EXCLUDED.last_update_tx_hash 
                                   ELSE user_aggregate_positions.last_update_tx_hash END;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS aggregate_position_trigger ON user_token_positions;
CREATE TRIGGER aggregate_position_trigger
    AFTER INSERT OR UPDATE ON user_token_positions
    FOR EACH ROW
    EXECUTE FUNCTION update_aggregate_position();

CREATE OR REPLACE FUNCTION notify_user_balance_update() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    payload := json_build_object(
        'user_blockchain_address', NEW.user_blockchain_address,
        'user_external_address', '',
        'contract_address', NEW.contract_address,
        'external_address', NEW.external_address,
        'amount', NEW.amount::text,
        'updated_at', EXTRACT(EPOCH FROM NEW.updated_at)::bigint
    );
    
    PERFORM pg_notify('user_balance_updates', payload::text);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION notify_aggregate_balance_update()
RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    payload := json_build_object(
        'user_blockchain_address', '',
        'user_external_address', NEW.user_external_address,
        'contract_address', NEW.contract_address,
        'external_address', NEW.external_address,
        'amount', NEW.amount::text,
        'updated_at', EXTRACT(EPOCH FROM NEW.updated_at)::bigint
    );

    PERFORM pg_notify('user_balance_updates', payload::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS aggregate_balance_notify_insert_trigger ON user_aggregate_positions;
CREATE TRIGGER aggregate_balance_notify_insert_trigger
    AFTER INSERT ON user_aggregate_positions
    FOR EACH ROW
    WHEN (NEW.amount != 0)
    EXECUTE FUNCTION notify_aggregate_balance_update();

DROP TRIGGER IF EXISTS aggregate_balance_notify_update_trigger ON user_aggregate_positions;
CREATE TRIGGER aggregate_balance_notify_update_trigger
    AFTER UPDATE OF amount ON user_aggregate_positions
    FOR EACH ROW
    WHEN (OLD.amount IS DISTINCT FROM NEW.amount)
    EXECUTE FUNCTION notify_aggregate_balance_update();

DROP FUNCTION IF EXISTS update_market_cap_and_position(TIMESTAMP, TEXT, TEXT, TEXT, BOOLEAN, NUMERIC, NUMERIC, usd_amount, usd_amount, NUMERIC);

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
    v_cost_usd NUMERIC;
    v_realized_usd NUMERIC;
    v_fee_usd NUMERIC;
    v_owner_external_address TEXT;
    v_owner_avatar TEXT;
    v_owner_username TEXT;
    v_owner_display_name TEXT;
    v_platform TEXT;
BEGIN
    SELECT u.external_address INTO v_user_external_address
    FROM user_bsc_addresses uba
    JOIN users u ON u.id = uba.user_id
    WHERE uba.bsc_address = LOWER(p_user_blockchain_address);

    v_market_cap_ion := (p_total_supply / 1e18) * p_price_usd / p_ion_price_usd;
    v_market_cap_usd := (p_total_supply / 1e18) * p_price_usd;

    IF POSITION(':' IN p_token_external_address) > 0 THEN
        v_owner_external_address := SPLIT_PART(p_token_external_address, ':', 1) || ':' || SPLIT_PART(p_token_external_address, ':', 2) || ':';
    ELSE
        v_owner_external_address := p_token_external_address;
    END IF;

    SELECT avatar, username, display_name, platform_group
    INTO v_owner_avatar, v_owner_username, v_owner_display_name, v_platform
    FROM users
    WHERE external_address = v_owner_external_address;

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

    v_fee_usd := (p_fee / 1e18) * p_ion_price_usd;

    IF p_direction = false THEN -- buy
        -- Cost: as-is (bonding curve output already reflects fee deduction on input side)
        v_cost_usd := (p_input_amount / 1e18) * p_ion_price_usd;

        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, total_fees_usd, updated_at
        )
        VALUES (
                   p_user_blockchain_address, p_token_address, p_token_external_address,
                   v_user_external_address,
                   0, p_price_usd, v_cost_usd, 0, v_fee_usd, p_block_timestamp
               )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
            total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
            total_fees_usd = user_token_positions.total_fees_usd + EXCLUDED.total_fees_usd,
            -- Weighted average: (old_invested + new_invested) / (old_tokens + new_tokens)
            avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) /
                                NULLIF(
                                    (user_token_positions.total_invested_usd / NULLIF(user_token_positions.avg_buy_price_usd, 0)) +
                                    (EXCLUDED.total_invested_usd / NULLIF(p_price_usd, 0)),
                                    0
                                ),
            updated_at = EXCLUDED.updated_at,
            user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    ELSE -- sell
        v_realized_usd := (p_output_amount / 1e18) * p_ion_price_usd;

        UPDATE user_token_positions
        SET total_realized_usd = COALESCE(total_realized_usd, 0) + v_realized_usd,
            total_fees_usd = COALESCE(total_fees_usd, 0) + v_fee_usd,
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
END; $$ LANGUAGE plpgsql;

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
    v_records_count INT;
    v_is_intermediate BOOLEAN;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Invalid topics array length: % | tx=%', array_length(p_topics, 1), p_transaction_hash;
        RETURN;
    END IF;

    v_swapper := LOWER('0x' || substring(p_topics[2] from 27 for 40));
    v_pair_id := LOWER(p_topics[3]);
    v_direction := (decode_uint256(p_data, 0) != 0);
    -- Event includes feeToken at index 1:
    -- Word 0: direction, Word 1: inputAmount, Word 2: outputAmount, Word 3: fee
    v_input_amount := decode_uint256(p_data, 1);
    v_output_amount := decode_uint256(p_data, 2);
    v_fee := decode_uint256(p_data, 3);

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Processing tx=% | swapper=% | pair_id=% | direction=% | input=% | output=% | fee=%',
        p_transaction_hash, v_swapper, v_pair_id, v_direction, v_input_amount, v_output_amount, v_fee;

    BEGIN
        v_token_external_address := decode_to_token_from_input(p_tx_input);
        v_base_token := decode_base_token_from_input(p_tx_input);
        v_records_count := (p_tx_input->>'recordsCount')::INT;

        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Decoded from tx input | tx=% | token_external=% | base_token=% | records_count=%',
            p_transaction_hash, v_token_external_address, v_base_token, v_records_count;
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Failed to decode from tx input | tx=% | error=%', p_transaction_hash, SQLERRM;
        v_token_external_address := NULL;
        v_base_token := NULL;
        v_records_count := 1;
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
          AND t.pair_id = v_pair_id;
    END IF;

    -- If not found by external_address + pair_id, find by pair_id only
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
        RAISE WARNING 'Base price not found, skipping swap for tx %', p_transaction_hash;
        RETURN;
    END IF;

    v_user_address := v_swapper;

    IF v_input_amount = 0 OR v_output_amount = 0 THEN
        RAISE WARNING 'Invalid swap amounts (input=%, output=%) for tx %, skipping', v_input_amount, v_output_amount, p_transaction_hash;
        RETURN;
    END IF;

    -- Price as-is: bonding curve output already reflects fee impact
    IF v_direction = false THEN -- buy
        v_price_usd := (v_input_amount / v_output_amount) * v_base_price_usd;
    ELSE -- sell
        v_price_usd := (v_output_amount / v_input_amount) * v_base_price_usd;
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Calculated price | tx=% | token=% | price_usd=% | direction=% | fee=%',
        p_transaction_hash, v_token_address, v_price_usd, v_direction, v_fee;

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

    v_is_intermediate := (v_records_count > 1 AND v_token_type = 'profile');

    IF v_is_intermediate THEN
        RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Intermediate swap in twisted swap (records_count=%, type=%) | tx=% | token=% | SKIPPING position update',
            v_records_count, v_token_type, p_transaction_hash, v_token_address;
    END IF;

    IF NOT v_is_intermediate THEN
        PERFORM update_market_cap_and_position(p_block_timestamp, v_user_address, v_token_address, v_token_external_address,
                                               v_direction, v_input_amount, v_output_amount, v_price_usd, v_base_price_usd, v_total_supply, v_fee);
    END IF;

    IF v_token_type = 'profile' THEN
        PERFORM update_base_token_price(v_token_address, v_token_ticker, v_price_usd, (v_price_usd / v_base_price_usd * 1e18)::uint256);
    END IF;

    RAISE NOTICE '[EVENT_PROCESSOR] Swapped: Successfully processed | tx=% | token=% | user=% | external=%',
        p_transaction_hash, v_token_address, v_user_address, v_token_external_address;
END;
$$ LANGUAGE plpgsql;
