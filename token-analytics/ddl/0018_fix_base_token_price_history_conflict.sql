-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION update_base_token_price(
    p_token_address TEXT,
    p_token_ticker TEXT,
    p_price_usd usd_amount
) RETURNS VOID AS
$$
BEGIN
    WITH old_price AS (
        SELECT price_usd
        FROM base_token_prices
        WHERE token_address = $1
    ),
         updated AS (
             INSERT INTO base_token_prices (token_address, token_symbol, price_usd, updated_at)
                 VALUES (p_token_address, p_token_ticker, p_price_usd, NOW())
                 ON CONFLICT (token_address) DO UPDATE SET
                     price_usd = EXCLUDED.price_usd,
                     updated_at = EXCLUDED.updated_at,
                     token_symbol = EXCLUDED.token_symbol
                 RETURNING price_usd
         )
    INSERT INTO base_token_price_history (token_address, price_usd, created_at)
    SELECT p_token_address, p_price_usd, NOW()
    WHERE NOT EXISTS (SELECT 1 FROM old_price)
       OR (SELECT price_usd FROM old_price) != p_price_usd
    ON CONFLICT DO NOTHING;
END;
$$ LANGUAGE plpgsql;

