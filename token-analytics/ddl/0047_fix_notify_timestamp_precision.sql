-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION notify_token_swap_update() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
    v_base_token TEXT;
    v_total_supply TEXT;
    v_pair_id TEXT;
    v_burned TEXT;
    v_platform TEXT;
    v_type TEXT;
BEGIN
    SELECT t.base_token, t.total_supply, t.pair_id, COALESCE(burned.amount, 0)::text,
           t.platform, t."type"
    INTO v_base_token, v_total_supply, v_pair_id, v_burned, v_platform, v_type
    FROM tokens t
    LEFT JOIN fees_transferred burned ON burned.token_external_address = t.external_address
        AND burned.recipient_bsc_address = '0x0000000000000000000000000000000000696f6e'
    WHERE t.contract_address = NEW.contract_address;

    payload := json_build_object(
            'transaction_hash', NEW.transaction_hash,
            'contract_address', NEW.contract_address,
            'external_address', NEW.external_address,
            'user_blockchain_address', NEW.user_blockchain_address,
            'direction', NEW.direction,
            'input_amount', NEW.input_amount::text,
            'output_amount', NEW.output_amount::text,
            'curve_price_usd', NEW.curve_price_usd,
            'created_at', (EXTRACT(EPOCH FROM NEW.created_at) * 1000000)::bigint,
            'base_token', COALESCE(v_base_token, ''),
            'total_supply', COALESCE(v_total_supply, '0'),
            'pair_id', COALESCE(v_pair_id, ''),
            'burned', v_burned,
            'platform', v_platform,
            'type', v_type
         );

    PERFORM pg_notify('token_swap_updates', payload::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
