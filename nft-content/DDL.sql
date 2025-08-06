-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nft_content_type') THEN
        CREATE TYPE nft_content_type AS ENUM ('account', 'post', 'article', 'video', 'story');
    ELSE
        IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'story' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'nft_content_type')) THEN
            ALTER TYPE nft_content_type ADD VALUE 'story';
        END IF;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nft_content_status') THEN
        CREATE TYPE nft_content_status AS ENUM ('new','pending', 'completed');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS nft_content (
    content_address                        TEXT NOT NULL,
    nft_collection_address                 TEXT NOT NULL DEFAULT '',
    nft_collection_name                    TEXT NOT NULL DEFAULT '',
    nft_collection_creator_address         TEXT NOT NULL DEFAULT '',
    master_pubkey                          TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    type                                   nft_content_type NOT NULL,
    status                                 nft_content_status NOT NULL DEFAULT 'new',
    PRIMARY KEY (content_address, type)
) WITH (FILLFACTOR = 70);

ALTER TABLE nft_content ADD COLUMN IF NOT EXISTS nft_collection_name TEXT NOT NULL DEFAULT '';

DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
            WHERE tc.table_name = 'nft_content' 
                AND tc.constraint_type = 'PRIMARY KEY'
                AND kcu.column_name = 'content_address'
                AND NOT EXISTS (
                    SELECT 1 FROM information_schema.key_column_usage kcu2
                    WHERE kcu2.constraint_name = tc.constraint_name
                    AND kcu2.column_name = 'type'
                )
    ) THEN
        ALTER TABLE nft_content DROP CONSTRAINT nft_content_pkey;
        ALTER TABLE nft_content ADD CONSTRAINT nft_content_pkey PRIMARY KEY (content_address, type);
    END IF;
END $$;