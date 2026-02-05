-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS bonding_curve_notified_at TIMESTAMP;
ALTER TABLE user_token_positions ADD COLUMN IF NOT EXISTS balance_notified_at TIMESTAMP;

CREATE OR REPLACE FUNCTION set_bonding_curve_notified_at() RETURNS TRIGGER AS $$
BEGIN
    IF (OLD.bonding_curve_current_amount IS DISTINCT FROM NEW.bonding_curve_current_amount OR
        OLD.bonding_curve_goal_amount IS DISTINCT FROM NEW.bonding_curve_goal_amount OR
        OLD.bonding_curve_current_amount_usd IS DISTINCT FROM NEW.bonding_curve_current_amount_usd OR
        OLD.bonding_curve_goal_amount_usd IS DISTINCT FROM NEW.bonding_curve_goal_amount_usd OR
        OLD.bonding_curve_migrated IS DISTINCT FROM NEW.bonding_curve_migrated OR
        OLD.liquidity_usd IS DISTINCT FROM NEW.liquidity_usd) THEN
        
        NEW.bonding_curve_notified_at := NOW();
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_set_bonding_curve_notified_at
    BEFORE UPDATE ON tokens
    FOR EACH ROW
    EXECUTE FUNCTION set_bonding_curve_notified_at();

CREATE INDEX IF NOT EXISTS idx_tokens_bonding_curve_notified_at ON tokens (bonding_curve_notified_at ASC NULLS FIRST) WHERE bonding_curve_current_amount_usd IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_user_token_positions_balance_notified_at ON user_token_positions (balance_notified_at ASC NULLS FIRST);

UPDATE tokens 
SET bonding_curve_notified_at = updated_at
WHERE bonding_curve_current_amount_usd IS NOT NULL 
AND bonding_curve_notified_at IS NULL;

UPDATE user_token_positions 
SET balance_notified_at = updated_at
WHERE balance_notified_at IS NULL;
