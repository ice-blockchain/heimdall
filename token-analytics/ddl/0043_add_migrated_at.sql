-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE tokens ADD COLUMN IF NOT EXISTS migrated_at TIMESTAMP;

UPDATE tokens SET migrated_at = updated_at WHERE bonding_curve_migrated = true AND migrated_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tokens_migrated_at ON tokens (migrated_at DESC) WHERE migrated_at IS NOT NULL;
