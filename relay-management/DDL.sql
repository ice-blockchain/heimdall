-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ion_connect_relay_type') THEN
        CREATE TYPE ion_connect_relay_type AS ENUM ('read', 'write');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ion_connect_relay_ref') THEN
        CREATE TYPE ion_connect_relay_ref AS (
                                                 url          TEXT,
                                                 type         ion_connect_relay_type
                                             );
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS ion_connect_relays (
                                                  created_at           TIMESTAMP NOT NULL,
                                                  updated_at           TIMESTAMP NOT NULL,
                                                  unhealthy_started_at TIMESTAMP,
                                                  total_used_storage   BIGINT NOT NULL DEFAULT 0,
                                                  url                  TEXT NOT NULL,
                                                  region               TEXT NOT NULL,
                                                  nip_11               JSONB,
                                                  relay_type           ion_connect_relay_type NOT NULL,
                                                  relay_group          TEXT NOT NULL,
                                            primary key(url)
);

DO $$ BEGIN
    if NOT exists (SELECT column_name FROM information_schema.columns WHERE table_name='ion_connect_relays' and column_name='relay_type') then
        ALTER TABLE IF EXISTS ion_connect_relays ADD COLUMN relay_group TEXT;
        ALTER TABLE IF EXISTS ion_connect_relays ADD COLUMN relay_type ion_connect_relay_type;
        UPDATE ion_connect_relays SET
                                      relay_group = '',
                                      relay_type = 'write'::ion_connect_relay_type
                                  WHERE relay_group = '';
        ALTER TABLE ion_connect_relays ALTER COLUMN relay_group SET NOT NULL;
        ALTER TABLE ion_connect_relays ALTER COLUMN relay_type SET NOT NULL;

    end if;
END $$;


CREATE INDEX IF NOT EXISTS idx_ion_connect_relays_region_unhealthy_started_at ON ion_connect_relays(region, unhealthy_started_at desc nulls first);
CREATE INDEX IF NOT EXISTS ion_connect_relays_with_the_lowest_storage_by_region_inner_cte_total ON ion_connect_relays(unhealthy_started_at desc nulls first, relay_group, total_used_storage ASC);
CREATE INDEX IF NOT EXISTS ion_connect_relays_date_search ON ion_connect_relays USING brin(unhealthy_started_at);

DO $$ BEGIN
    IF not exists(select 1 from pg_matviews where matviewname = 'ion_connect_relays_with_the_lowest_storage_by_region' AND definition LIKE '%relay_type%') then
        DROP MATERIALIZED VIEW IF EXISTS ion_connect_relays_with_the_lowest_storage_by_region;
        CREATE MATERIALIZED VIEW IF NOT EXISTS ion_connect_relays_with_the_lowest_storage_by_region AS
        WITH group_totals AS (
            SELECT relay_group,
                   SUM(total_used_storage) as group_total_storage
            FROM ion_connect_relays
            WHERE (unhealthy_started_at is NULL OR unhealthy_started_at between now() - '3 minute'::INTERVAL and now())
            GROUP BY relay_group
        ),
        best_group AS (
            SELECT relay_group
            FROM group_totals
            ORDER BY group_total_storage ASC
            LIMIT 1
        ),
        ranked_ion_connect_relays AS (
            SELECT url,
                   region,
                   total_used_storage,
                   relay_type,
                   ion_connect_relays.relay_group,
                   ROW_NUMBER() OVER (PARTITION BY region ORDER BY total_used_storage ASC) as rank
            FROM ion_connect_relays
            JOIN best_group ON best_group.relay_group = ion_connect_relays.relay_group
            WHERE (unhealthy_started_at is NULL OR unhealthy_started_at between now() - '3 minute'::INTERVAL and now()) AND ion_connect_relays.relay_group = best_group.relay_group
        )
        SELECT url,
               region,
               relay_type,
               relay_group
        FROM ranked_ion_connect_relays
        WHERE rank = 1;
    end if;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ion_connect_relays_with_the_lowest_storage_by_region ON ion_connect_relays_with_the_lowest_storage_by_region(region);