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
        'updated_at', EXTRACT(EPOCH FROM NEW.updated_at)::bigint
    );
    
    PERFORM pg_notify('token_bonding_curve_updates', payload::text);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS token_price_update_trigger ON tokens;
DROP TRIGGER IF EXISTS token_bonding_curve_update_trigger ON tokens;

CREATE TRIGGER token_bonding_curve_update_trigger
    AFTER UPDATE OF bonding_curve_current_amount, bonding_curve_goal_amount, 
                     bonding_curve_raised_amount, bonding_curve_current_amount_usd, 
                     bonding_curve_goal_amount_usd, bonding_curve_migrated, liquidity_usd ON tokens
    FOR EACH ROW
    WHEN (
        OLD.bonding_curve_current_amount IS DISTINCT FROM NEW.bonding_curve_current_amount OR
        OLD.bonding_curve_goal_amount IS DISTINCT FROM NEW.bonding_curve_goal_amount OR
        OLD.bonding_curve_raised_amount IS DISTINCT FROM NEW.bonding_curve_raised_amount OR
        OLD.bonding_curve_current_amount_usd IS DISTINCT FROM NEW.bonding_curve_current_amount_usd OR
        OLD.bonding_curve_goal_amount_usd IS DISTINCT FROM NEW.bonding_curve_goal_amount_usd OR
        OLD.bonding_curve_migrated IS DISTINCT FROM NEW.bonding_curve_migrated OR
        OLD.liquidity_usd IS DISTINCT FROM NEW.liquidity_usd
    )
    EXECUTE FUNCTION notify_bonding_curve_update();

CREATE OR REPLACE FUNCTION notify_user_balance_update() RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    payload := json_build_object(
        'user_blockchain_address', NEW.user_blockchain_address,
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

DROP TRIGGER IF EXISTS user_balance_update_trigger ON user_token_positions;

CREATE TRIGGER user_balance_update_trigger
    AFTER INSERT OR UPDATE OF amount ON user_token_positions
    FOR EACH ROW
    EXECUTE FUNCTION notify_user_balance_update();

