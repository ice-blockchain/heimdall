-- SPDX-License-Identifier: ice License 1.0

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
        t.external_address
    INTO v_creator_bsc_address, v_affiliate_bsc_address, v_external_address
    FROM tokens t
    WHERE t.pair_id = v_pair_id;
    IF v_external_address IS NULL OR v_creator_bsc_address IS NULL THEN
        RAISE WARNING 'Token with pair % not found, skipping fee processing', v_pair_id;
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

    INSERT INTO fees_transferred (updated_at, token_external_address, recipient_bsc_address, fee_type, amount)
    VALUES (p_block_timestamp, v_external_address, v_recipient, v_fee_type, v_fee_amount)
    ON CONFLICT (token_external_address, recipient_bsc_address) DO UPDATE
        SET amount = fees_transferred.amount + v_fee_amount,
            updated_at = excluded.updated_at;

    RAISE DEBUG 'FeeTransfer processed: token=%, recipient=%', v_external_address, v_recipient;
END;
$$ LANGUAGE plpgsql;
