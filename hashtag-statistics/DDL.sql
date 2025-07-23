-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS hashtag_statistics (
    occurrences   BIGINT NOT NULL DEFAULT 1,
    lookup        TSVECTOR NOT NULL GENERATED ALWAYS AS (TO_TSVECTOR('english', hashtag)) STORED,
    hashtag       TEXT NOT NULL PRIMARY KEY
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS idx_hashtag_statistics_lookup ON hashtag_statistics USING GIN(lookup);
CREATE INDEX IF NOT EXISTS idx_hashtag_statistics_occurrences ON hashtag_statistics(occurrences desc);

CREATE TABLE IF NOT EXISTS processed_hashtag_statistics_events (
    event_address               TEXT NOT NULL PRIMARY KEY, -- id or kind:pubkey:dtag
    event_author_master_pubkey  TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    hashtags                    TEXT[] NOT NULL 
);
