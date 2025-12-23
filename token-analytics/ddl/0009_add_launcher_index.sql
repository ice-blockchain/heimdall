-- SPDX-License-Identifier: ice License 1.0

CREATE INDEX IF NOT EXISTS idx_token_swaps_contract_direction_created 
ON token_swaps (contract_address, direction, created_at ASC);
