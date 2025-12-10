-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS liquidity_usd usd_amount DEFAULT 0;

