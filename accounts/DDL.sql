-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users (
    id                                     TEXT NOT NULL,
    email                                  TEXT,
    phone_number                           TEXT,
    totp_authentificator_secret            TEXT,
    primary key(id)
) WITH (FILLFACTOR = 70);

CREATE TABLE IF NOT EXISTS twofa_codes (
    created_at timestamp NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    option TEXT NOT NULL,
    deliver_to TEXT NOT NULL,
    code    TEXT NOT NULL,
    primary key (user_id, option)
)