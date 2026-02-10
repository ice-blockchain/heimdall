-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS user_bsc_addresses (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bsc_address TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (bsc_address)
);
CREATE INDEX IF NOT EXISTS idx_user_bsc_user_id ON user_bsc_addresses (user_id);

INSERT INTO user_bsc_addresses (user_id, bsc_address, created_at)
SELECT id, LOWER(content_author_id), created_at FROM users
WHERE content_author_id IS NOT NULL AND content_author_id != ''
ON CONFLICT DO NOTHING;

DROP INDEX IF EXISTS idx_users_external_address_ionconnect_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_address_unique ON users (external_address);

DROP INDEX IF EXISTS idx_users_content_author_id_lower;
DROP INDEX IF EXISTS idx_users_external_address_content_author;
DROP INDEX IF EXISTS idx_tokens_contract_address_lower;
CREATE INDEX IF NOT EXISTS idx_tokens_contract_address ON tokens (contract_address);

ALTER TABLE users DROP COLUMN IF EXISTS content_author_id;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_content_author_id_not_empty;

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
    p_total_supply NUMERIC
) RETURNS VOID AS $$
DECLARE
    v_user_external_address TEXT;
    v_market_cap_usd usd_amount;
    v_market_cap_ion NUMERIC;
    v_cost_usd NUMERIC;
    v_realized_usd NUMERIC;
    v_owner_external_address TEXT;
    v_owner_avatar TEXT;
    v_owner_username TEXT;
    v_owner_display_name TEXT;
    v_platform TEXT;
BEGIN
    SELECT u.external_address INTO v_user_external_address
    FROM user_bsc_addresses uba
    JOIN users u ON u.id = uba.user_id
    WHERE uba.bsc_address = LOWER(p_user_blockchain_address);

    v_market_cap_ion := (p_total_supply / 1e18) * p_price_usd / p_ion_price_usd;
    v_market_cap_usd := (p_total_supply / 1e18) * p_price_usd;

    IF POSITION(':' IN p_token_external_address) > 0 THEN
        v_owner_external_address := SPLIT_PART(p_token_external_address, ':', 1) || ':' || SPLIT_PART(p_token_external_address, ':', 2) || ':';
    ELSE
        v_owner_external_address := p_token_external_address;
    END IF;

    SELECT avatar, username, display_name, platform_group
    INTO v_owner_avatar, v_owner_username, v_owner_display_name, v_platform
    FROM users
    WHERE external_address = v_owner_external_address;

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

    v_cost_usd := (p_input_amount / 1e18) * p_ion_price_usd;

    IF p_direction = false THEN -- buy
        INSERT INTO user_token_positions (
            user_blockchain_address, contract_address, external_address, user_external_address,
            amount, avg_buy_price_usd, total_invested_usd, total_realized_usd, updated_at
        )
        VALUES (
                   p_user_blockchain_address, p_token_address, p_token_external_address,
                   v_user_external_address,
                   0, p_price_usd, v_cost_usd, 0, p_block_timestamp
               )
        ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
            total_invested_usd = user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd,
            avg_buy_price_usd = (user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) /
                                NULLIF((user_token_positions.total_invested_usd + EXCLUDED.total_invested_usd) / NULLIF(p_price_usd, 0), 0),
            updated_at = EXCLUDED.updated_at,
            user_external_address = COALESCE(EXCLUDED.user_external_address, user_token_positions.user_external_address);
    ELSE -- sell
        v_realized_usd := (p_output_amount / 1e18) * p_ion_price_usd;

        UPDATE user_token_positions
        SET total_realized_usd = COALESCE(total_realized_usd, 0) + v_realized_usd,
            updated_at = p_block_timestamp
        WHERE user_blockchain_address = p_user_blockchain_address
          AND contract_address = p_token_address;
    END IF;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_tokens_lookup_on_user_change()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE tokens
    SET lookup = LOWER(TRIM(
        COALESCE(contract_address, '') || ' ' ||
        COALESCE(ticker, '') || ' ' ||
        COALESCE(NEW.username, '') || ' ' ||
        COALESCE(NEW.display_name, '')
    ))
    WHERE content_author_id IN (
        SELECT bsc_address FROM user_bsc_addresses WHERE user_id = NEW.id
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
