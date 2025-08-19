-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS following (
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    master_pubkey          TEXT      NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    follower_master_pubkey TEXT      NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    primary key(master_pubkey,follower_master_pubkey),
    CHECK (master_pubkey != follower_master_pubkey)
);

CREATE UNIQUE INDEX IF NOT EXISTS following_follower_master_pubkey ON following (follower_master_pubkey,master_pubkey);
