-- SPDX-License-Identifier: ice License 1.0

DROP INDEX IF EXISTS idx_users_master_pubkey_unique;
CREATE UNIQUE INDEX idx_users_master_pubkey_unique ON users (master_pubkey);

UPDATE user_token_positions utp
SET user_external_address = u.master_pubkey
FROM users u
WHERE u.platform_group = 'ionconnect'
  AND utp.user_external_address = '0:' || u.master_pubkey || ':';

DROP TRIGGER IF EXISTS aggregate_position_trigger ON user_token_positions;
DROP TRIGGER IF EXISTS aggregate_balance_notify_insert_trigger ON user_aggregate_positions;
DROP TRIGGER IF EXISTS aggregate_balance_notify_update_trigger ON user_aggregate_positions;
DROP TRIGGER IF EXISTS user_balance_notify_trigger ON user_token_positions;

TRUNCATE user_aggregate_positions;

INSERT INTO user_aggregate_positions (
    user_external_address, external_address, contract_address,
    amount, total_invested_usd, total_realized_usd, total_fees_usd,
    updated_at, last_update_block, last_update_tx_hash
)
SELECT
    utp.user_external_address,
    utp.external_address,
    MIN(utp.contract_address),
    SUM(utp.amount::NUMERIC)::uint256,
    SUM(COALESCE(utp.total_invested_usd, 0)),
    SUM(COALESCE(utp.total_realized_usd, 0)),
    SUM(COALESCE(utp.total_fees_usd, 0)),
    MAX(utp.updated_at),
    MAX(COALESCE(utp.last_update_block, 0)),
    ''
FROM user_token_positions utp
WHERE utp.user_external_address IS NOT NULL AND utp.user_external_address != ''
GROUP BY utp.user_external_address, utp.external_address;

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
    v_owner_external_address TEXT;
    v_owner_avatar TEXT;
    v_owner_username TEXT;
    v_owner_display_name TEXT;
    v_platform TEXT;
BEGIN
    SELECT u.master_pubkey INTO v_user_external_address
    FROM user_bsc_addresses uba
    JOIN users u ON u.id = uba.user_id
    WHERE uba.bsc_address = LOWER(p_user_blockchain_address);

    IF v_user_external_address IS NULL AND LOWER(p_user_blockchain_address) = LOWER(p_token_address) THEN
        v_user_external_address := p_token_external_address;
    END IF;

    v_market_cap_ion := (p_total_supply / 1e18) * p_price_usd / p_ion_price_usd;
    v_market_cap_usd := (p_total_supply / 1e18) * p_price_usd;

    IF POSITION(':' IN p_token_external_address) > 0 THEN
        v_owner_external_address := SPLIT_PART(p_token_external_address, ':', 2);
    ELSE
        v_owner_external_address := p_token_external_address;
    END IF;

    SELECT avatar, username, display_name, platform_group
    INTO v_owner_avatar, v_owner_username, v_owner_display_name, v_platform
    FROM users
    WHERE master_pubkey = v_owner_external_address;

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

    IF p_direction = false THEN
        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, total_invested_usd, total_realized_usd, total_fees_usd, updated_at
        )
        VALUES (
            p_user_blockchain_address, p_token_address, p_token_external_address,
            v_user_external_address,
            0, 0, 0, 0, p_block_timestamp
        )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
            updated_at = EXCLUDED.updated_at,
            user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    END IF;
END; $$ LANGUAGE plpgsql;

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
            WHERE master_pubkey = NEW.user_external_address;
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
            WHERE master_pubkey = NEW.user_external_address;
        ELSIF OLD.amount = 0 AND NEW.amount > 0 THEN
            UPDATE tokens
            SET holders_count = holders_count + 1,
                updated_at = NOW()
            WHERE contract_address = NEW.contract_address;

            UPDATE users
            SET token_holdings_count = token_holdings_count + 1
            WHERE master_pubkey = NEW.user_external_address;
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
            WHERE master_pubkey = OLD.user_external_address;
        END IF;
        PERFORM update_token_platform_holders_count(OLD.external_address, OLD.user_external_address, OLD.amount, 0);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_token_platform_holders_count(
    p_token_external_address TEXT,
    p_user_external_address TEXT,
    p_old_amount NUMERIC,
    p_new_amount NUMERIC
)
RETURNS VOID AS $$
DECLARE
    v_platform_group platform_type;
BEGIN
    IF p_user_external_address IS NULL OR p_user_external_address = '' THEN
        RETURN;
    END IF;

    SELECT platform_group INTO v_platform_group
    FROM users
    WHERE master_pubkey = p_user_external_address;

    IF v_platform_group IS NULL THEN
        RETURN;
    END IF;

    IF p_old_amount = 0 AND p_new_amount > 0 THEN
        INSERT INTO token_platform_holders (external_address, platform_group, holders_count, updated_at)
        VALUES (p_token_external_address, v_platform_group, 1, NOW())
        ON CONFLICT (external_address, platform_group) DO UPDATE
        SET holders_count = token_platform_holders.holders_count + 1,
            updated_at = NOW();

    ELSIF p_old_amount > 0 AND p_new_amount = 0 THEN
        UPDATE token_platform_holders
        SET holders_count = GREATEST(holders_count - 1, 0),
            updated_at = NOW()
        WHERE external_address = p_token_external_address
          AND platform_group = v_platform_group;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER aggregate_position_trigger
    AFTER INSERT OR UPDATE ON user_token_positions
    FOR EACH ROW
    EXECUTE FUNCTION update_aggregate_position();

CREATE TRIGGER aggregate_balance_notify_insert_trigger
    AFTER INSERT ON user_aggregate_positions
    FOR EACH ROW
    WHEN (NEW.amount != 0)
    EXECUTE FUNCTION notify_aggregate_balance_update();

CREATE TRIGGER aggregate_balance_notify_update_trigger
    AFTER UPDATE OF amount ON user_aggregate_positions
    FOR EACH ROW
    WHEN (OLD.amount IS DISTINCT FROM NEW.amount)
    EXECUTE FUNCTION notify_aggregate_balance_update();


UPDATE user_aggregate_positions SET updated_at = NOW(); -- Trigger dragonfly positions repopulation.

DROP INDEX IF EXISTS idx_users_external_address;
DROP INDEX IF EXISTS idx_users_external_address_unique;
DROP INDEX IF EXISTS idx_users_external_address_content_author;
ALTER TABLE users DROP COLUMN IF EXISTS external_address;
