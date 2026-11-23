CREATE TABLE zone_policy (
    zone_id VARCHAR(100) PRIMARY KEY,
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1
);
INSERT INTO zone_policy (zone_id) SELECT DISTINCT zone_id FROM asset_instance;
