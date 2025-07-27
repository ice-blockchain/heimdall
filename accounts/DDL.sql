-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users (
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    id                                     TEXT NOT NULL,
    identity_key_name                      TEXT NOT NULL UNIQUE,
    master_pubkey                          TEXT NOT NULL UNIQUE,
    clients                                TEXT[] NOT NULL,
    email                                  TEXT[],
    phone_number                           TEXT[],
    totp_authenticator_secret              TEXT[],
    ion_connect_relays                     TEXT[],
    active_2fa_email                       boolean[], -- bitmask
    active_2fa_phone_number                boolean[], -- bitmask
    active_2fa_totp_authenticator          boolean[], -- bitmask
    verified                               boolean NOT NULL DEFAULT false,
    CONSTRAINT active_2fa_email_valid CHECK (cardinality(active_2fa_email) = cardinality(email)),
    CONSTRAINT active_2fa_phone_valid CHECK (cardinality(active_2fa_phone_number) = cardinality(phone_number)),
    CONSTRAINT active_2fa_totp_valid CHECK (cardinality(users.active_2fa_totp_authenticator) = cardinality(totp_authenticator_secret)),
    primary key(id)
) WITH (FILLFACTOR = 70);

DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'twofa_option') THEN
            CREATE TYPE twofa_option AS ENUM ('email', 'sms', 'totp_authenticator');
        END IF;
END$$;

CREATE TABLE IF NOT EXISTS twofa_codes (
    created_at timestamp NOT NULL,
    confirmed_at timestamp,
    option twofa_option NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    deliver_to TEXT NOT NULL,
    code    TEXT NOT NULL,
    replace TEXT,
    primary key (user_id, option, deliver_to)
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS twofa_codes_option_code ON twofa_codes (option, deliver_to, code);

CREATE TABLE IF NOT EXISTS global  (
       value TEXT NOT NULL,
       key text primary key
) WITH (FILLFACTOR = 70);

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
    coins         coin_mapping[],
    id            TEXT NOT NULL,
    name          TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    symbol_groups TEXT[],
    primary key (id)
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS wallet_views_user_id ON wallet_views (user_id);

CREATE TABLE IF NOT EXISTS content_creators (
    master_pubkey                           TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    primary key(master_pubkey)
);

CREATE TABLE IF NOT EXISTS verified_users_sync_queue (
    created_at                       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id                          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    primary key(user_id)
);

CREATE INDEX IF NOT EXISTS verified_users_sync_queue_created_at ON verified_users_sync_queue (created_at);

CREATE TABLE IF NOT EXISTS social_profiles (
    created_at             TIMESTAMP NOT NULL,
    updated_at             TIMESTAMP NOT NULL,
    master_pubkey          TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    username               TEXT NOT NULL UNIQUE,
    display_name           TEXT,
    referral_master_pubkey TEXT REFERENCES users(master_pubkey) ON DELETE SET NULL,
    lookup                 TEXT NOT NULL DEFAULT '',
    primary key(master_pubkey)
) WITH (FILLFACTOR = 70);

CREATE EXTENSION IF NOT EXISTS pgroonga;
CREATE INDEX IF NOT EXISTS idx_social_profiles_lookup_pgroonga ON social_profiles USING pgroonga (lookup) WITH (tokenizer='TokenBigramSplitSymbolAlphaDigit');

CREATE TABLE IF NOT EXISTS early_access_emails (
                                                   created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                                   email      TEXT NOT NULL primary key
);

CREATE TABLE IF NOT EXISTS assigned_early_access_emails (
                                                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                                            email   TEXT NOT NULL REFERENCES early_access_emails(email) ON DELETE CASCADE,
                                                            primary key(email, user_id)
);