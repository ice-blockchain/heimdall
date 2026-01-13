-- SPDX-License-Identifier: ice License 1.0

CREATE INDEX IF NOT EXISTS idx_user_token_positions_user_ext_addr_amount 
ON user_token_positions (user_external_address, amount DESC) 
WHERE amount > '0';

ALTER TABLE users ADD COLUMN IF NOT EXISTS token_holdings_count INT DEFAULT 0;

CREATE OR REPLACE FUNCTION update_token_holders_count_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;
            
            UPDATE users
            SET token_holdings_count = token_holdings_count + 1
            WHERE external_address = NEW.user_external_address;
        END IF;
        PERFORM update_token_platform_holders_count(NEW.external_address, NEW.user_external_address, 0, NEW.amount);
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.amount > 0 AND NEW.amount = 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;
            
            UPDATE users
            SET token_holdings_count = GREATEST(token_holdings_count - 1, 0)
            WHERE external_address = NEW.user_external_address;
        ELSIF OLD.amount = 0 AND NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;
            
            UPDATE users
            SET token_holdings_count = token_holdings_count + 1
            WHERE external_address = NEW.user_external_address;
        END IF;
        PERFORM update_token_platform_holders_count(NEW.external_address, NEW.user_external_address, OLD.amount, NEW.amount);
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.amount > 0 THEN
            UPDATE tokens
            SET holders_count = GREATEST(holders_count - 1, 0),
                updated_at = NOW()
            WHERE contract_address = OLD.contract_address;
            
            UPDATE users
            SET token_holdings_count = GREATEST(token_holdings_count - 1, 0)
            WHERE external_address = OLD.user_external_address;
        END IF;
        PERFORM update_token_platform_holders_count(OLD.external_address, OLD.user_external_address, OLD.amount, 0);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

UPDATE users u
SET token_holdings_count = (
    SELECT COUNT(*)
    FROM user_token_positions utp
    WHERE utp.user_external_address = u.external_address
      AND utp.amount > '0'
)
WHERE EXISTS (
    SELECT 1
    FROM user_token_positions utp
    WHERE utp.user_external_address = u.external_address
);

