-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nft_content_type') THEN
        CREATE TYPE nft_content_type AS ENUM ('account', 'post', 'article', 'video', 'story');
    ELSE
        -- TODO: remove this it will be migrated to all envs.
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
    nft_item_address                       TEXT NOT NULL DEFAULT '',
    nft_collection_name                    TEXT NOT NULL DEFAULT '',
    nft_collection_creator_address         TEXT NOT NULL DEFAULT '',
    owner                                  TEXT NOT NULL,
    master_pubkey                          TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    type                                   nft_content_type NOT NULL,
    status                                 nft_content_status NOT NULL DEFAULT 'new',
    created_at                             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (content_address, type)
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS nft_content_master_pubkey_idx ON nft_content (master_pubkey);
CREATE INDEX IF NOT EXISTS nft_content_new_assignment_idx ON nft_content (content_address) WHERE status = 'new' AND nft_collection_creator_address = '';
CREATE INDEX IF NOT EXISTS nft_content_creator_sorted_idx ON nft_content (nft_collection_creator_address, master_pubkey, type, content_address, status) WHERE nft_collection_creator_address IS NOT NULL AND nft_collection_creator_address <> '';

-- TODO: remove this it will be migrated to all envs.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'nft_content'
        AND column_name = 'nft_collection_item_address'
    ) THEN
        ALTER TABLE nft_content RENAME COLUMN nft_collection_item_address TO nft_item_address;
    END IF;
END $$;

-- TODO: remove this it will be migrated to all envs.
ALTER TABLE nft_content ADD COLUMN IF NOT EXISTS nft_collection_name TEXT NOT NULL DEFAULT '';
ALTER TABLE nft_content ADD COLUMN IF NOT EXISTS nft_item_address TEXT NOT NULL DEFAULT '';
DO $$
BEGIN
    ALTER TABLE nft_content ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';
    UPDATE nft_content SET owner = nft_collection_creator_address WHERE owner = '';
    ALTER TABLE nft_content ALTER COLUMN owner DROP DEFAULT;
END $$;

-- TODO: remove this it will be migrated to all envs.
ALTER TABLE nft_content ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- TODO: remove this it will be migrated to all envs.
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

CREATE TABLE IF NOT EXISTS nft_minters
(
    id        SERIAL PRIMARY KEY,
    pubkey    TEXT NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS nft_minters_active_pubkey_idx ON nft_minters (is_active, pubkey);

CREATE OR REPLACE FUNCTION assign_and_prepare_pending_nfts(limit_per_minter INTEGER)
    RETURNS TABLE
            (
                minter_pubkey TEXT,
                nft_contents  JSON
            )
    LANGUAGE plpgsql
AS
$$
DECLARE
    total_minters INTEGER;
BEGIN
    -- Step 1: Count active minters
    SELECT COUNT(*) INTO total_minters FROM nft_minters WHERE is_active = TRUE;
    IF total_minters = 0 THEN
        RETURN;
    END IF;

    -- Step 2: Assign new NFTs to minters using round-robin logic
    WITH active_minters AS (SELECT pubkey,
                                   ROW_NUMBER() OVER (ORDER BY pubkey) - 1 AS minter_rn
                            FROM nft_minters
                            WHERE is_active = TRUE),
         new_content AS (SELECT content_address,
                                ROW_NUMBER() OVER (ORDER BY content_address) - 1 AS rn
                         FROM nft_content
                         WHERE status = 'new'
                           AND nft_collection_creator_address = '')
    UPDATE nft_content
    SET nft_collection_creator_address = am.pubkey
    FROM new_content nc
             JOIN active_minters am
                  ON am.minter_rn = (nc.rn % total_minters)
    WHERE nft_content.content_address = nc.content_address;

    -- Step 3: Rank NFTs by minter after assignment
    WITH ranked_per_minter AS (SELECT nc.*,
                                      ROW_NUMBER() OVER (
                                          PARTITION BY nft_collection_creator_address
                                          ORDER BY master_pubkey,
                                              CASE type
                                                  WHEN 'account' THEN 1
                                                  WHEN 'story' THEN 2
                                                  ELSE 3
                                                  END,
                                              content_address
                                          ) AS rn
                               FROM nft_content nc
                               WHERE status = 'new'
                                 AND nft_collection_creator_address IS NOT NULL
                                 AND nft_collection_creator_address <> '')
    UPDATE nft_content
    SET status = 'pending'
    FROM ranked_per_minter rpm
    WHERE nft_content.content_address = rpm.content_address
      AND rpm.rn <= limit_per_minter;

    -- Step 4: Return grouped result per minter
    RETURN QUERY
        WITH ranked_pending AS (SELECT nc.*,
                                       ROW_NUMBER() OVER (
                                           PARTITION BY nft_collection_creator_address
                                           ORDER BY master_pubkey,
                                               CASE type
                                                   WHEN 'account' THEN 1
                                                   WHEN 'story' THEN 2
                                                   ELSE 3
                                                   END,
                                               content_address
                                           ) AS rn
                                FROM nft_content nc
                                WHERE status = 'pending'
                                  AND nft_collection_creator_address IS NOT NULL
                                  AND nft_collection_creator_address <> '')
        SELECT rp.nft_collection_creator_address AS minter_pubkey,
               json_agg(
                       json_build_object(
                               'content_address', rp.content_address,
                               'nft_collection_address', rp.nft_collection_address,
                               'nft_collection_creator_address', rp.nft_collection_creator_address,
                               'collection_name', rp.nft_collection_name,
                               'master_pubkey', rp.master_pubkey,
                               'owner', rp.owner,
                               'type', rp.type,
                               'status', rp.status
                       )
                       ORDER BY rp.master_pubkey,
                           CASE rp.type
                               WHEN 'account' THEN 1
                               WHEN 'story' THEN 2
                               ELSE 3
                               END,
                           rp.content_address
               )                                 AS nft_contents
        FROM ranked_pending rp
        WHERE rp.rn <= limit_per_minter
        GROUP BY rp.nft_collection_creator_address;

END;
$$;