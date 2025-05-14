-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS verified_users_sync_queue (
    created_at                       TIMESTAMP NOT NULL DEFAULT now(),
    user_id                          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    primary key(user_id)
);

CREATE INDEX IF NOT EXISTS verified_users_sync_queue_created_at ON verified_users_sync_queue (created_at);
