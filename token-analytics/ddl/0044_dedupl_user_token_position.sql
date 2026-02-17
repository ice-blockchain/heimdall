-- SPDX-License-Identifier: ice License 1.0

ALTER TABLE user_token_positions ADD COLUMN IF NOT EXISTS last_update_block BIGINT NOT NULL DEFAULT 0;
ALTER TABLE user_token_positions ADD COLUMN IF NOT EXISTS last_update_tx_hash TEXT NOT NULL DEFAULT '';