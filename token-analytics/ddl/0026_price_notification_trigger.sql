-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION notify_token_price_update() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    payload := json_build_object(
        'external_address', NEW.external_address,
        'contract_address', NEW.contract_address,
        'price_usd', NEW.price_usd,
        'total_supply', NEW.total_supply::text,
        'liquidity_usd', COALESCE(NEW.liquidity_usd, 0),
        'bonding_curve_migrated', COALESCE(NEW.bonding_curve_migrated, false),
        'bonding_curve_current_amount', COALESCE(NEW.bonding_curve_current_amount::text, '0'),
        'bonding_curve_goal_amount', COALESCE(NEW.bonding_curve_goal_amount::text, '0'),
        'bonding_curve_raised_amount', COALESCE(NEW.bonding_curve_raised_amount::text, '0'),
        'bonding_curve_current_amount_usd', COALESCE(NEW.bonding_curve_current_amount_usd, 0),
        'bonding_curve_goal_amount_usd', COALESCE(NEW.bonding_curve_goal_amount_usd, 0),
        'updated_at', EXTRACT(EPOCH FROM NEW.updated_at)
    );
    
    PERFORM pg_notify('token_price_updates', payload::text);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS token_price_update_trigger ON tokens;

CREATE TRIGGER token_price_update_trigger
    AFTER UPDATE OF price_usd, bonding_curve_current_amount, bonding_curve_goal_amount, 
                     bonding_curve_raised_amount, bonding_curve_current_amount_usd, 
                     bonding_curve_goal_amount_usd, bonding_curve_migrated, liquidity_usd ON tokens
    FOR EACH ROW
    WHEN (
        OLD.price_usd IS DISTINCT FROM NEW.price_usd OR
        OLD.bonding_curve_current_amount IS DISTINCT FROM NEW.bonding_curve_current_amount OR
        OLD.bonding_curve_goal_amount IS DISTINCT FROM NEW.bonding_curve_goal_amount OR
        OLD.bonding_curve_raised_amount IS DISTINCT FROM NEW.bonding_curve_raised_amount OR
        OLD.bonding_curve_current_amount_usd IS DISTINCT FROM NEW.bonding_curve_current_amount_usd OR
        OLD.bonding_curve_goal_amount_usd IS DISTINCT FROM NEW.bonding_curve_goal_amount_usd OR
        OLD.bonding_curve_migrated IS DISTINCT FROM NEW.bonding_curve_migrated OR
        OLD.liquidity_usd IS DISTINCT FROM NEW.liquidity_usd
    )
    EXECUTE FUNCTION notify_token_price_update();

