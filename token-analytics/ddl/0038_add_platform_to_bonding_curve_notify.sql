-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION notify_bonding_curve_update() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    payload := json_build_object(
            'external_address', NEW.external_address,
            'type', COALESCE(NEW.type, ''),
            'platform', NEW.platform::text,
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
            'fee_sponsor', NEW.fee_sponsor,
            'updated_at', EXTRACT(EPOCH FROM NEW.updated_at)::bigint
        );

    PERFORM pg_notify('token_bonding_curve_updates', payload::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP MATERIALIZED VIEW IF EXISTS token_volumes_24h CASCADE;

CREATE MATERIALIZED VIEW token_volumes_24h AS
SELECT
    ts.contract_address,
    t.external_address,
    t."type" as token_type,
    t.platform,
    COALESCE(SUM(
        CASE
            WHEN ts.direction = true THEN ts.input_amount::numeric * ts.price_usd
            ELSE ts.output_amount::numeric * ts.price_usd
        END
    ), 0) as volume_24h,
    MAX(ts.created_at) as last_updated
FROM token_swaps ts
JOIN tokens t ON t.contract_address = ts.contract_address
WHERE ts.created_at >= NOW() - INTERVAL '24 hours'
GROUP BY ts.contract_address, t.external_address, t."type", t.platform;

CREATE UNIQUE INDEX idx_token_volumes_24h_contract ON token_volumes_24h (contract_address);
CREATE INDEX idx_token_volumes_24h_volume ON token_volumes_24h (volume_24h DESC);
CREATE INDEX idx_token_volumes_24h_external ON token_volumes_24h (external_address);
