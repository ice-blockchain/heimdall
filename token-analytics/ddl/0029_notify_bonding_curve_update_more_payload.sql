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
