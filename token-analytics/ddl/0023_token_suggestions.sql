-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS user_tokens_suggestions (
    content_id TEXT PRIMARY KEY,

    ticker TEXT,
    name TEXT,
    picture_url TEXT,
    picture_b64 TEXT,

    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    attempt_count INT DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    last_attempted_at TIMESTAMPTZ,

    CONSTRAINT status_check CHECK (status IN ('pending', 'generating_ticker', 'generating_picture', 'uploading', 'completed', 'failed'))
);
