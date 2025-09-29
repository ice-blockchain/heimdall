-- SPDX-License-Identifier: ice License 1.0

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ion_connect_relay_type') THEN
        CREATE TYPE ion_connect_relay_type AS ENUM ('read', 'write');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS ion_connect_relays (
                                                  created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                                  updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                                  unhealthy_started_at TIMESTAMP,
                                                  total_used_storage   BIGINT NOT NULL DEFAULT 0,
                                                  relay_type           ion_connect_relay_type NOT NULL,
                                                  url                  TEXT NOT NULL,
                                                  region               TEXT NOT NULL,
                                                  relay_group          TEXT NOT NULL,
                                                  nip_11               JSONB,
                                            primary key(url)
) WITH (FILLFACTOR = 70);

CREATE INDEX IF NOT EXISTS idx_ion_connect_region_unhealthy_started_at ON ion_connect_relays(region, unhealthy_started_at desc nulls first);
CREATE INDEX IF NOT EXISTS ion_connect_relays_with_the_lowest_storage_by_region_inner_cte_total ON ion_connect_relays(unhealthy_started_at desc nulls first, relay_group, total_used_storage ASC);
CREATE INDEX IF NOT EXISTS ion_connect_relays_date_search ON ion_connect_relays USING brin(unhealthy_started_at);

DO $$ BEGIN
    DROP MATERIALIZED VIEW IF EXISTS ion_connect_relays_with_the_lowest_storage_by_region;
    CREATE MATERIALIZED VIEW IF NOT EXISTS ion_connect_relays_with_the_lowest_storage_by_region AS
    WITH group_totals AS (
        SELECT relay_group,
               SUM(total_used_storage) as group_total_storage
        FROM ion_connect_relays
        --WHERE (unhealthy_started_at is NULL OR unhealthy_started_at between now() - '3 minute'::INTERVAL and now())
        GROUP BY relay_group
    ),
    best_group AS (
        SELECT relay_group
        FROM group_totals
        ORDER BY group_total_storage ASC
        LIMIT 1
    ),
    ion_connect_relays_from_best_group AS (
        SELECT url,
               region,
               total_used_storage,
               relay_type,
               ion_connect_relays.relay_group
        FROM ion_connect_relays
        JOIN best_group ON best_group.relay_group = ion_connect_relays.relay_group
        WHERE --(unhealthy_started_at is NULL OR unhealthy_started_at between now() - '3 minute'::INTERVAL and now()) AND
              ion_connect_relays.relay_group = best_group.relay_group
    )
    SELECT url,
           region,
           relay_type,
           relay_group
    FROM ion_connect_relays_from_best_group;
END$$;