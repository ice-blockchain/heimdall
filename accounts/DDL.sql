-- SPDX-License-Identifier: ice License 1.0
drop table twofa_codes;
drop table users;
drop type twofa_option;


CREATE TABLE IF NOT EXISTS users (
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    id                                     TEXT NOT NULL,
    username                               TEXT NOT NULL UNIQUE,
    clients                                TEXT[] NOT NULL,
    email                                  TEXT[],
    phone_number                           TEXT[],
    totp_authenticator_secret              TEXT[],
    ion_connect_relays                     TEXT[],
    active_2fa_email                       smallint,
    active_2fa_phone_number                smallint,
    active_2fa_totp_authenticator          smallint,
    CONSTRAINT active_2fa_email_valid CHECK (active_2fa_email < cardinality(email)),
    CONSTRAINT active_2fa_phone_valid CHECK (active_2fa_phone_number < cardinality(phone_number)),
    CONSTRAINT active_2fa_totp_valid CHECK (users.active_2fa_totp_authenticator < cardinality(totp_authenticator_secret)),
    primary key(id)
);

DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'twofa_option') THEN
            CREATE TYPE twofa_option AS ENUM ('email', 'sms', 'totp_authenticator');
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