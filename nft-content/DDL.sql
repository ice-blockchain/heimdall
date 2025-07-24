-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nft_content_type') THEN
        CREATE TYPE nft_content_type AS ENUM ('account', 'post', 'article', 'video');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nft_content_status') THEN
        CREATE TYPE nft_content_status AS ENUM ('new','pending', 'completed');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS nft_content (
    content_address                        TEXT NOT NULL PRIMARY KEY,
    nft_collection_address                 TEXT NOT NULL DEFAULT '',
    nft_collection_creator_address         TEXT NOT NULL DEFAULT '',
    master_pubkey                          TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    type                                   nft_content_type NOT NULL,
    status                                 nft_content_status NOT NULL DEFAULT 'new'
) WITH (FILLFACTOR = 70);

-- TODO: add proper indexes later on 