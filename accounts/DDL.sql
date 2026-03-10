-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS users (
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    id                                     TEXT NOT NULL,
    identity_key_name                      TEXT NOT NULL UNIQUE,
    master_pubkey                          TEXT NOT NULL UNIQUE,
    duplicate_of                           TEXT REFERENCES users(id) ON DELETE SET NULL,
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

CREATE TABLE IF NOT EXISTS wallets (
    created_at    TIMESTAMP NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    network TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_scheme TEXT NOT NULL,
    key_curve TEXT NOT NULL,
    user_id TEXT NOT NULL,
    primary key (id)
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS wallets_user_id ON wallets (user_id);

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

CREATE TABLE IF NOT EXISTS global_accounts (
    master_pubkey                           TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    primary key(master_pubkey)
);
-- TODO remove this
DROP table if exists priority_accounts;

CREATE OR REPLACE FUNCTION increment_global_accounts_version()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO global (key, value)
    VALUES ('latest_global_accounts_version', '1')
    ON CONFLICT (key)
    DO UPDATE SET value = (COALESCE(CAST(global.value AS INTEGER), 0) + 1)::TEXT;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER global_accounts_insert_version_trigger
AFTER INSERT OR DELETE ON global_accounts
FOR EACH ROW
EXECUTE FUNCTION increment_global_accounts_version();

CREATE OR REPLACE TRIGGER global_accounts_truncate_version_trigger
AFTER TRUNCATE ON global_accounts
FOR EACH STATEMENT
EXECUTE FUNCTION increment_global_accounts_version();

CREATE TABLE IF NOT EXISTS nsfw_accounts (
    master_pubkey                           TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    primary key(master_pubkey)
);

CREATE OR REPLACE FUNCTION increment_nsfw_accounts_version()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO global (key, value)
    VALUES ('latest_nsfw_accounts_version', '1')
    ON CONFLICT (key)
    DO UPDATE SET value = (COALESCE(CAST(global.value AS INTEGER), 0) + 1)::TEXT;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER nsfw_accounts_insert_version_trigger
AFTER INSERT OR DELETE ON nsfw_accounts
FOR EACH ROW
EXECUTE FUNCTION increment_nsfw_accounts_version();

CREATE OR REPLACE TRIGGER nsfw_accounts_truncate_version_trigger
AFTER TRUNCATE ON nsfw_accounts
FOR EACH STATEMENT
EXECUTE FUNCTION increment_nsfw_accounts_version();

CREATE TABLE IF NOT EXISTS verified_users_sync_queue (
    created_at                       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id                          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    primary key(user_id)
);

CREATE INDEX IF NOT EXISTS verified_users_sync_queue_created_at ON verified_users_sync_queue (created_at);

CREATE TABLE IF NOT EXISTS social_profiles (
    created_at             TIMESTAMP NOT NULL,
    updated_at             TIMESTAMP NOT NULL,
    referral_count         BIGINT NOT NULL DEFAULT 0,
    master_pubkey          TEXT NOT NULL REFERENCES users(master_pubkey) ON DELETE CASCADE,
    username               TEXT NOT NULL UNIQUE,
    display_name           TEXT,
    bio                    TEXT,
    avatar                 TEXT,
    referral_master_pubkey TEXT REFERENCES users(master_pubkey) ON DELETE SET NULL,
    lookup                 TEXT NOT NULL DEFAULT '',
    primary key(master_pubkey)
) WITH (FILLFACTOR = 70);

-- TODO: remove this it will be migrated to all envs.
ALTER TABLE social_profiles ADD COLUMN IF NOT EXISTS bio TEXT;
ALTER TABLE social_profiles ADD COLUMN IF NOT EXISTS avatar TEXT;

-- TODO: remove this it will be migrated to all envs.
DROP INDEX IF EXISTS idx_social_profiles_lookup_pgroonga;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- TODO: Remove this DROP INDEX after migration to idx_social_profiles_lookup_gist_trgm index is completed.
DROP INDEX IF EXISTS idx_social_profiles_lookup_trgm;
CREATE INDEX IF NOT EXISTS idx_social_profiles_lookup_gist_trgm ON social_profiles USING GiST (lookup gist_trgm_ops);

-- TODO: remove this it will be migrated to all envs.
DO $$ BEGIN
    IF NOT exists (select 1 from information_schema.columns where table_name = 'social_profiles' and column_name = 'referral_count') then
        ALTER TABLE social_profiles ADD COLUMN IF NOT EXISTS referral_count BIGINT NOT NULL DEFAULT 0;
        UPDATE social_profiles
            SET referral_count = update_data.ref_count
        FROM (SELECT social_profiles.referral_master_pubkey, count(*) AS ref_count
              FROM social_profiles
              WHERE referral_master_pubkey IS NOT NULL
              GROUP BY social_profiles.referral_master_pubkey) update_data (referral_master_pubkey, ref_count)
        WHERE social_profiles.master_pubkey = update_data.referral_master_pubkey
            AND referral_count = 0;
    END IF;
END$$;

CREATE OR REPLACE FUNCTION trigger_social_after_insert_update_ref_count()
    RETURNS TRIGGER AS $$
BEGIN
        IF NEW.referral_master_pubkey IS NULL THEN
            IF OLD.referral_master_pubkey IS NULL THEN
                RETURN NEW;
            ELSE
                UPDATE social_profiles
                SET referral_count = GREATEST(referral_count - 1, 0)
                WHERE master_pubkey = OLD.referral_master_pubkey;

                RETURN NEW;
            END IF;
        ELSE
            UPDATE social_profiles
            SET referral_count = referral_count + 1
            WHERE master_pubkey = NEW.referral_master_pubkey;
            RETURN NEW;
        END IF;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_social_after_insert_update_ref_count
    AFTER INSERT OR UPDATE OF referral_master_pubkey OR DELETE ON social_profiles
    FOR EACH ROW
EXECUTE FUNCTION trigger_social_after_insert_update_ref_count();

CREATE TABLE IF NOT EXISTS early_access_emails (
                                                   created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                                   email      TEXT NOT NULL primary key
);

CREATE TABLE IF NOT EXISTS assigned_early_access_emails (
                                                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                                            email   TEXT NOT NULL,
                                                            primary key(email, user_id)
);

ALTER TABLE assigned_early_access_emails DROP CONSTRAINT IF EXISTS assigned_early_access_emails_email_fkey;

CREATE TABLE IF NOT EXISTS users_visitors (
                                              created_at       TIMESTAMP NOT NULL,
                                              user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                              visitor_id       TEXT NOT NULL,
                                              device_pubkey    TEXT NOT NULL,
                                              primary key (user_id, visitor_id)
);
CREATE INDEX IF NOT EXISTS users_visitors_visitor_id ON users_visitors (visitor_id, created_at asc);
ALTER TABLE users ADD COLUMN IF NOT EXISTS duplicate_of TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE OR REPLACE FUNCTION reserve_username(p_username TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_now TIMESTAMP := CURRENT_TIMESTAMP;
    v_reserved_id TEXT := 'reserved_' || gen_random_uuid()::TEXT;
    v_username TEXT := lower(p_username);
BEGIN
    IF v_username = '' THEN
        RAISE EXCEPTION 'USERNAME_REQUIRED';
    END IF;

    INSERT INTO users(
        created_at, updated_at, id, identity_key_name, master_pubkey, clients
    ) VALUES (
        v_now, v_now, v_reserved_id, v_reserved_id, v_reserved_id, ARRAY[]::TEXT[]
    );
    INSERT INTO social_profiles(
        created_at, updated_at, master_pubkey, username
    ) VALUES (
        v_now, v_now, v_reserved_id, v_username
    );
END;
$$;

CREATE OR REPLACE FUNCTION add_verified(VARIADIC p_usernames TEXT[])
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_normalized_usernames TEXT[];
    v_not_found_users TEXT[];
    v_already_verified_users TEXT[];
BEGIN
    IF array_length(p_usernames, 1) IS NULL THEN
        RAISE EXCEPTION 'USERNAMES_REQUIRED';
    END IF;

    SELECT array_agg(lower(trim(username)))
    INTO v_normalized_usernames
    FROM unnest(p_usernames) AS username
    WHERE trim(username) != '';

    SELECT array_agg(sp.username)
    INTO v_already_verified_users
    FROM users u
    JOIN social_profiles sp
    ON u.master_pubkey = sp.master_pubkey
    WHERE sp.username = ANY(v_normalized_usernames) AND u.verified = true;

    INSERT INTO verified_users_sync_queue(user_id)
    SELECT DISTINCT u.id
    FROM users u
    JOIN social_profiles sp
    ON u.master_pubkey = sp.master_pubkey
    WHERE sp.username = ANY(v_normalized_usernames) AND u.verified = false
    ON CONFLICT (user_id) DO NOTHING;

    SELECT array_agg(username)
    INTO v_not_found_users
    FROM unnest(v_normalized_usernames) AS username
    WHERE username NOT IN (
        SELECT sp.username
        FROM social_profiles sp
        WHERE sp.username = ANY(v_normalized_usernames)
    );

    IF array_length(v_already_verified_users, 1) > 0 THEN
        RAISE NOTICE 'Users already verified: %', array_to_string(v_already_verified_users, ', ');
    END IF;

    IF array_length(v_not_found_users, 1) > 0 THEN
        RAISE NOTICE 'Users not found: %', array_to_string(v_not_found_users, ', ');
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION add_content_creator(VARIADIC p_usernames TEXT[])
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_normalized_usernames TEXT[];
    v_not_found_users TEXT[];
BEGIN
    IF array_length(p_usernames, 1) IS NULL THEN
        RAISE EXCEPTION 'USERNAMES_REQUIRED';
    END IF;

    SELECT array_agg(lower(trim(username)))
    INTO v_normalized_usernames
    FROM unnest(p_usernames) AS username
    WHERE trim(username) != '';

    INSERT INTO content_creators(master_pubkey)
    SELECT DISTINCT u.master_pubkey
    FROM users u
    JOIN social_profiles sp ON u.master_pubkey = sp.master_pubkey
    WHERE sp.username = ANY(v_normalized_usernames)
    ON CONFLICT (master_pubkey) DO NOTHING;

    SELECT array_agg(username)
    INTO v_not_found_users
    FROM unnest(v_normalized_usernames) AS username
    WHERE username NOT IN (
        SELECT sp.username
        FROM social_profiles sp
        WHERE sp.username = ANY(v_normalized_usernames)
    );

    IF array_length(v_not_found_users, 1) > 0 THEN
        RAISE NOTICE 'Users not found: %', array_to_string(v_not_found_users, ', ');
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION add_nsfw_accounts(VARIADIC p_usernames TEXT[])
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_normalized_usernames TEXT[];
    v_not_found_users TEXT[];
BEGIN
    IF array_length(p_usernames, 1) IS NULL THEN
        RAISE EXCEPTION 'USERNAMES_REQUIRED';
    END IF;

    SELECT array_agg(lower(trim(username)))
    INTO v_normalized_usernames
    FROM unnest(p_usernames) AS username
    WHERE trim(username) != '';

    INSERT INTO nsfw_accounts(master_pubkey)
    SELECT DISTINCT u.master_pubkey
    FROM users u
    JOIN social_profiles sp ON u.master_pubkey = sp.master_pubkey
    WHERE sp.username = ANY(v_normalized_usernames)
    ON CONFLICT (master_pubkey) DO NOTHING;

    SELECT array_agg(username)
    INTO v_not_found_users
    FROM unnest(v_normalized_usernames) AS username
    WHERE username NOT IN (
        SELECT sp.username
        FROM social_profiles sp
        WHERE sp.username = ANY(v_normalized_usernames)
    );

    IF array_length(v_not_found_users, 1) > 0 THEN
        RAISE NOTICE 'Users not found: %', array_to_string(v_not_found_users, ', ');
    END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS deeplinks (
    event_address TEXT PRIMARY KEY,
    deeplink TEXT NOT NULL
);
