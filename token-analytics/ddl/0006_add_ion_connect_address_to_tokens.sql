-- SPDX-License-Identifier: ice License 1.0

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'tokens' AND column_name = 'ion_connect_address') THEN
        ALTER TABLE tokens ADD COLUMN ion_connect_address TEXT;
    END IF;
END $$;

