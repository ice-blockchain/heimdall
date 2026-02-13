-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS fee_in_other_token BOOLEAN DEFAULT FALSE;
UPDATE tokens SET fee_in_other_token = TRUE WHERE
     fee_in_other_token = FALSE
     AND platform = 'ionconnect'
     AND ("type" IN ('post', 'article', 'video'));

ALTER table fees_transferred ADD COLUMN IF NOT EXISTS swapped_token TEXT;
UPDATE fees_transferred SET swapped_token = token_external_address WHERE swapped_token IS NULL;
ALTER TABLE fees_transferred ALTER COLUMN swapped_token SET NOT NULL;

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
    v_fee_in_other_token BOOL;
BEGIN
    IF array_length(p_topics, 1) < 4 THEN
        RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Invalid topics array length: %', array_length(p_topics, 1);
        RETURN;
    END IF;

    v_pair_id := LOWER(p_topics[2]);
    v_base_token := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_other_token := LOWER('0x' || substring(p_topics[4] from 27 for 40));
    v_fee_in_other_token := (decode_uint256(p_data, 0) != 0);
    v_price_model := LOWER('0x' || substring(p_data from 64+27 for 64+40)); -- priceModel at offset 1
    v_start_price := decode_uint256(p_data, 2); -- startPrice at offset 2
    v_end_price := decode_uint256(p_data, 3); -- endPrice at offset 3

    RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Processing token=% | pair_id=% | base_token=% | price_model=% | start_price=% | end_price=%',
        v_other_token, v_pair_id, v_base_token, v_price_model, v_start_price, v_end_price;

    UPDATE tokens
    SET
        base_token = v_base_token,
        pair_id = v_pair_id,
        price_model = v_price_model,
        start_price = v_start_price,
        end_price = v_end_price,
        fee_in_other_token = v_fee_in_other_token,
        updated_at = p_block_timestamp
    WHERE LOWER(contract_address) = v_other_token;

    RAISE NOTICE '[EVENT_PROCESSOR] PairRegistered: Successfully processed token=% | pair_id=%', v_other_token, v_pair_id;
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION process_fee_transfer(
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_fee_amount NUMERIC;
    v_recipient TEXT;
    v_creator_bsc_address TEXT;
    v_affiliate_bsc_address TEXT;
    v_pair_id TEXT;
    v_external_address TEXT;
    v_fee_type TEXT;
    v_swapped_token TEXT;
    v_base_token TEXT;
    v_fee_in_other BOOLEAN;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;
    v_pair_id := LOWER(p_topics[2]);
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_fee_amount := decode_uint256(p_data, 0);
    SELECT
        t.content_author_id,
        t.affiliate_bsc_address,
        CASE WHEN t.fee_in_other_token = TRUE THEN t.external_address ELSE base_token.external_address END AS external_address,
        t.external_address as swapped_token,
        t.base_token,
        t.fee_in_other_token
    INTO v_creator_bsc_address, v_affiliate_bsc_address, v_external_address, v_swapped_token, v_base_token, v_fee_in_other
    FROM tokens t
    LEFT JOIN tokens base_token on t.base_token = base_token.contract_address
    WHERE t.pair_id = v_pair_id;
    IF v_external_address IS NULL OR v_swapped_token IS NULL OR v_creator_bsc_address IS NULL THEN
        RAISE WARNING 'Token with pair % not found, skipping fee processing, base %, other flag %', v_pair_id, v_base_token, v_fee_in_other;
        RETURN;
    END IF;
    v_fee_type := 'creator';
    IF LOWER(v_affiliate_bsc_address) = v_recipient THEN
        v_fee_type = 'affiliate';
        IF v_affiliate_bsc_address = '0x0000000000000000000000000000000000696f6e' THEN
            v_fee_type = 'burn';
        end if;
    ELSIF LOWER(v_creator_bsc_address) = v_recipient THEN
        v_fee_type = 'creator';
    ELSIF v_recipient = '0x0000000000000000000000000000000000696f6e' THEN
        v_fee_type = 'burn';
    END IF;

    INSERT INTO fees_transferred (updated_at, token_external_address, swapped_token,recipient_bsc_address, fee_type, amount)
    VALUES (p_block_timestamp, v_external_address,v_swapped_token, v_recipient, v_fee_type, v_fee_amount)
    ON CONFLICT (token_external_address, recipient_bsc_address) DO UPDATE
        SET amount = fees_transferred.amount + v_fee_amount,
            swapped_token = excluded.swapped_token,
            updated_at = excluded.updated_at;

    RAISE DEBUG 'FeeTransfer processed: token=%, recipient=%', v_external_address, v_recipient;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION process_erc20_transfer(
    p_contract_address TEXT,
    p_topics TEXT[],
    p_data TEXT,
    p_block_timestamp TIMESTAMP
) RETURNS VOID AS $$
DECLARE
    v_amount NUMERIC;
    v_recipient TEXT;
    v_external_address TEXT;
    v_fee_type TEXT;
BEGIN
    IF array_length(p_topics, 1) < 3 THEN
        RETURN;
    END IF;
    v_recipient := LOWER('0x' || substring(p_topics[3] from 27 for 40));
    v_amount := decode_uint256(p_data, 0);
    IF v_recipient = '0x0000000000000000000000000000000000000000' THEN
        v_recipient := '0x0000000000000000000000000000000000696f6e';
    END IF;
    IF v_recipient != '0x0000000000000000000000000000000000696f6e' THEN -- handle only burned for now to increase burned fee
        RETURN;
    END IF;
    SELECT
        t.external_address
    INTO v_external_address
    FROM tokens t
    WHERE t.contract_address = p_contract_address;
    IF v_external_address IS NULL THEN
        RAISE WARNING 'Token with contract_address % not found, skipping fee erc20 processing', p_contract_address;
        RETURN;
    END IF;
    v_fee_type := 'burn';

    INSERT INTO fees_transferred (updated_at, token_external_address, swapped_token, recipient_bsc_address, fee_type, amount)
    VALUES (p_block_timestamp, v_external_address,  v_external_address, v_recipient, v_fee_type, v_amount)
    ON CONFLICT (token_external_address, recipient_bsc_address) DO UPDATE
        SET amount = fees_transferred.amount + v_amount,
            swapped_token = v_external_address,
            updated_at = excluded.updated_at;

    RAISE DEBUG 'Transfer (erc20) processed: token=%, recipient=%, amount=%', v_external_address, v_recipient, v_amount;
END;
$$ LANGUAGE plpgsql;