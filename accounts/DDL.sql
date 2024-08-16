-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users (
    id                                     TEXT NOT NULL,
    dfns_username                          TEXT NOT NULL UNIQUE,
    email                                  TEXT,
    phone_number                           TEXT,
    totp_authentificator_secret            TEXT,
    ion_relays                             TEXT[],
    primary key(id)
) WITH (FILLFACTOR = 70);


CREATE TABLE IF NOT EXISTS twofa_codes (
    created_at timestamp NOT NULL,
    confirmed_at timestamp,
    user_id TEXT NOT NULL REFERENCES users(id),
    option TEXT NOT NULL,
    deliver_to TEXT NOT NULL,
    code    TEXT NOT NULL,
    primary key (user_id, option)
);

CREATE INDEX IF NOT EXISTS twofa_codes_option_code ON twofa_codes (option, code);

CREATE TABLE IF NOT EXISTS global  (
       value TEXT NOT NULL,
       key text primary key
);