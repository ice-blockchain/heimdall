-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS ion_connect_relays (
                                                  created_at           TIMESTAMP NOT NULL,
                                                  updated_at           TIMESTAMP NOT NULL,
                                                  unhealthy_started_at TIMESTAMP,
                                                  total_used_storage   BIGINT NOT NULL DEFAULT 0,
                                                  url                  TEXT NOT NULL,
                                                  region               TEXT NOT NULL,
                                                  nip_11               JSONB,
                                            primary key(url)
);

CREATE INDEX IF NOT EXISTS idx_ion_connect_relays_region_unhealthy_started_at ON ion_connect_relays(region, unhealthy_started_at desc nulls first);
CREATE INDEX IF NOT EXISTS ion_connect_relays_with_the_lowest_storage_by_region_inner_cte ON ion_connect_relays(unhealthy_started_at desc nulls first, region, total_used_storage ASC);
CREATE INDEX IF NOT EXISTS ion_connect_relays_date_search ON ion_connect_relays USING brin(unhealthy_started_at);

CREATE MATERIALIZED VIEW IF NOT EXISTS ion_connect_relays_with_the_lowest_storage_by_region AS
WITH ranked_ion_connect_relays AS (
    SELECT url,
           region,
           total_used_storage,
           ROW_NUMBER() OVER (PARTITION BY region ORDER BY total_used_storage ASC) as rank
    FROM ion_connect_relays
    WHERE (unhealthy_started_at is NULL OR unhealthy_started_at between now() - '3 minute'::INTERVAL and now())
)
SELECT url,
       region
FROM ranked_ion_connect_relays
WHERE rank = 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ion_connect_relays_with_the_lowest_storage_by_region ON ion_connect_relays_with_the_lowest_storage_by_region(region);