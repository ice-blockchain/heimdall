-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS user_tokens_suggestions (
    attempt_count INT DEFAULT 0,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    last_attempted_at TIMESTAMP,

    content_id TEXT PRIMARY KEY,

    ticker TEXT,
    name TEXT,
    picture_url TEXT,
    picture_b64 TEXT,

    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT

    CONSTRAINT status_check CHECK (status IN ('pending', 'generating_ticker', 'generating_picture', 'uploading', 'completed', 'failed'))
);
