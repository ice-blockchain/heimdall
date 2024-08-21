-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users (
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    id                                     TEXT NOT NULL,
    username                          TEXT NOT NULL UNIQUE,
    clients                                TEXT[] NOT NULL,
    email                                  TEXT[],
    phone_number                           TEXT[],
    totp_authentificator_secret            TEXT[],
    ion_connect_relays                      TEXT[],
    primary key(id)
);

DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'twofa_option') THEN
            CREATE TYPE twofa_option AS ENUM ('email', 'sms', 'google_authentificator');
        END IF;
END$$;

CREATE TABLE IF NOT EXISTS twofa_codes (
    created_at timestamp NOT NULL,
    confirmed_at timestamp,
    user_id TEXT NOT NULL REFERENCES users(id),
    option twofa_option NOT NULL,
    deliver_to TEXT NOT NULL,
    code    TEXT NOT NULL,
    primary key (user_id, option)
);

CREATE INDEX IF NOT EXISTS twofa_codes_option_code ON twofa_codes (option, code);

CREATE TABLE IF NOT EXISTS global  (
       value TEXT NOT NULL,
       key text primary key
);