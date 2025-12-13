-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS bonding_curve_raised_amount uint256 DEFAULT 0;
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS bonding_curve_migrated BOOLEAN DEFAULT FALSE;