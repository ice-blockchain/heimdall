-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users (
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    id                                     TEXT NOT NULL,
    username                               TEXT NOT NULL UNIQUE,
    master_pubkey                          TEXT NOT NULL UNIQUE,
    clients                                TEXT[] NOT NULL,
    email                                  TEXT[],
    phone_number                           TEXT[],
    totp_authenticator_secret              TEXT[],
    ion_connect_relays                     TEXT[],
    active_2fa_email                       boolean[], -- bitmask
    active_2fa_phone_number                boolean[], -- bitmask
    active_2fa_totp_authenticator          boolean[], -- bitmask
    CONSTRAINT active_2fa_email_valid CHECK (cardinality(active_2fa_email) = cardinality(email)),
    CONSTRAINT active_2fa_phone_valid CHECK (cardinality(active_2fa_phone_number) = cardinality(phone_number)),
    CONSTRAINT active_2fa_totp_valid CHECK (cardinality(users.active_2fa_totp_authenticator) = cardinality(totp_authenticator_secret)),
    primary key(id)
);
DO $$ BEGIN
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS master_pubkey TEXT NOT NULL default '';
    UPDATE users SET master_pubkey = id WHERE users.master_pubkey = '';
    ALTER TABLE users
        ADD UNIQUE (master_pubkey);
END$$;

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
    primary key (user_id, option, deliver_to)
);

CREATE INDEX IF NOT EXISTS twofa_codes_option_code ON twofa_codes (option, deliver_to, code);

CREATE TABLE IF NOT EXISTS global  (
       value TEXT NOT NULL,
       key text primary key
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'coin_mapping') THEN
        CREATE TYPE coin_mapping AS (
                                            coinId          TEXT,
                                            walletId        TEXT
                                        );
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS wallet_views (
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL,
    name          TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id),
    symbol_groups TEXT[],
    coins         coin_mapping[],
    primary key (user_id, name)
);

ALTER TABLE wallet_views
    ADD COLUMN IF NOT EXISTS symbol_groups TEXT[];
ALTER TABLE wallet_views
    ADD COLUMN IF NOT EXISTS coins coin_mapping[];
ALTER TABLE wallet_views
    DROP COLUMN IF EXISTS items;