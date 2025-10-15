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
        CREATE TYPE nft_content_status AS ENUM ('new', 'pending', 'completed', 'failed');
    ELSE
        -- TODO: remove this it will be migrated to all envs.
        IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'failed' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'nft_content_status')) THEN
            ALTER TYPE nft_content_status ADD VALUE 'failed';
        END IF;
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

CREATE OR REPLACE FUNCTION assign_and_prepare_pending_nfts(
    limit_per_minter INTEGER,
    minter_count_limit INTEGER DEFAULT NULL,
    minter_offset INTEGER DEFAULT 0
)
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
    SELECT COUNT(*)
    INTO total_minters
    FROM nft_minters
    WHERE is_active = TRUE
      AND pubkey NOT IN
          ('UQA4sXqzs9NTxfUgP4s2XAjMPqOxIG7L84dO6s8fDa0DuCr3', 'UQATJyhHxJuB4Fw4qpMOvtp1nvBBZQBmQg0NFGN3Qbv-DNZc');
    IF total_minters = 0 THEN
        RETURN;
    END IF;

    -- Step 2: Assign new AND failed NFTs to minters using round-robin logic
    -- Include both NFTs without creator address and failed NFTs for rescheduling
    WITH active_minters AS (SELECT pubkey,
                                   ROW_NUMBER() OVER (ORDER BY pubkey) - 1 AS minter_rn
                            FROM nft_minters
                            WHERE is_active = TRUE
                              AND pubkey NOT IN ('UQA4sXqzs9NTxfUgP4s2XAjMPqOxIG7L84dO6s8fDa0DuCr3',
                                                 'UQATJyhHxJuB4Fw4qpMOvtp1nvBBZQBmQg0NFGN3Qbv-DNZc')),
         new_content AS (SELECT content_address,
                                ROW_NUMBER() OVER (ORDER BY content_address) - 1 AS rn
                         FROM nft_content
                         WHERE (status = 'new' AND nft_collection_creator_address = '')
                            OR status = 'failed')
    UPDATE nft_content
    SET nft_collection_creator_address = am.pubkey
    FROM new_content nc
             JOIN active_minters am
                  ON am.minter_rn = (nc.rn % total_minters)
    WHERE nft_content.content_address = nc.content_address
      AND ((nft_content.status = 'new' AND nft_content.nft_collection_creator_address = '')
        OR nft_content.status = 'failed');

    -- Step 3: Create temporary table to track newly assigned NFTs in this call
    CREATE TEMP TABLE IF NOT EXISTS newly_assigned_nfts
    (
        content_address TEXT PRIMARY KEY
    ) ON COMMIT DROP;

    TRUNCATE newly_assigned_nfts;

    -- Step 4: Atomically select and update NFTs from 'new'/'failed' to 'pending' with row locking
    -- This prevents race conditions when multiple processes run in parallel
    -- First, rank the records without locking
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
                               WHERE (status = 'new' OR status = 'failed')
                                 AND nft_collection_creator_address IS NOT NULL
                                 AND nft_collection_creator_address <> ''),
         -- Then select records to update with locking
         to_update AS (SELECT nc.*
                       FROM nft_content nc
                                INNER JOIN ranked_per_minter rpm ON nc.content_address = rpm.content_address
                       WHERE rpm.rn <= limit_per_minter
                         AND (nc.status = 'new' OR nc.status = 'failed') -- Double-check current status
                           FOR UPDATE OF nc SKIP LOCKED -- Lock only the nft_content rows, skip locked ones
         ),
         -- Finally, perform the update
         updated AS (
             UPDATE nft_content
                 SET status = 'pending'
                 FROM to_update tu
                 WHERE nft_content.content_address = tu.content_address
                 RETURNING nft_content.content_address)
    INSERT
    INTO newly_assigned_nfts (content_address)
    SELECT DISTINCT content_address
    FROM updated
    ON CONFLICT (content_address) DO NOTHING;

    -- Step 5: Return only the newly assigned NFTs with pagination
    RETURN QUERY
        WITH newly_pending AS (SELECT nc.*,
                                      ROW_NUMBER() OVER (
                                          PARTITION BY nc.nft_collection_creator_address
                                          ORDER BY nc.master_pubkey,
                                              CASE nc.type
                                                  WHEN 'account' THEN 1
                                                  WHEN 'story' THEN 2
                                                  ELSE 3
                                                  END,
                                              nc.content_address
                                          ) AS rn
                               FROM nft_content nc
                                        INNER JOIN newly_assigned_nfts na ON nc.content_address = na.content_address
                               WHERE nc.status = 'pending'
                                 AND nc.nft_collection_creator_address IS NOT NULL
                                 AND nc.nft_collection_creator_address <> ''),
             aggregated_minters AS (SELECT np.nft_collection_creator_address AS minter_pubkey,
                                           json_agg(
                                                   json_build_object(
                                                           'content_address', np.content_address,
                                                           'nft_collection_address', np.nft_collection_address,
                                                           'nft_collection_creator_address',
                                                           np.nft_collection_creator_address,
                                                           'collection_name', np.nft_collection_name,
                                                           'master_pubkey', np.master_pubkey,
                                                           'owner', np.owner,
                                                           'type', np.type,
                                                           'status', np.status
                                                   )
                                                   ORDER BY np.master_pubkey,
                                                       CASE np.type
                                                           WHEN 'account' THEN 1
                                                           WHEN 'story' THEN 2
                                                           ELSE 3
                                                           END,
                                                       np.content_address
                                           )                                 AS nft_contents
                                    FROM newly_pending np
                                    WHERE np.rn <= limit_per_minter
                                    GROUP BY np.nft_collection_creator_address
                                    ORDER BY np.nft_collection_creator_address)
        SELECT am.minter_pubkey,
               am.nft_contents
        FROM aggregated_minters am
        LIMIT minter_count_limit OFFSET minter_offset;

END;
$$;