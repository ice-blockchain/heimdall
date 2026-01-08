-- SPDX-License-Identifier: ice License 1.0

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_username_key'
    ) THEN
        ALTER TABLE users DROP CONSTRAINT users_username_key;
    END IF;
END $$;

