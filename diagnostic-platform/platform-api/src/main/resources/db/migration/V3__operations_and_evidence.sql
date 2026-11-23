CREATE TABLE asset_policy (
    asset_id VARCHAR(100) PRIMARY KEY,
    paused BOOLEAN NOT NULL,
    max_sessions INTEGER NOT NULL,
    revision BIGINT NOT NULL,
    CONSTRAINT fk_policy_asset FOREIGN KEY (asset_id) REFERENCES asset_instance(asset_id) ON DELETE CASCADE
);
INSERT INTO asset_policy (asset_id,paused,max_sessions,revision)
SELECT asset_id,FALSE,16,1 FROM asset_instance;

CREATE TABLE agent_channel (
    agent_id VARCHAR(100) PRIMARY KEY,
    last_seen BIGINT NOT NULL
);

CREATE TABLE evidence_reference (
    reference_id VARCHAR(36) PRIMARY KEY,
    task_id VARCHAR(36) NOT NULL,
    owner_id VARCHAR(100) NOT NULL,
    reader_id VARCHAR(100) NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked BOOLEAN NOT NULL,
    CONSTRAINT fk_reference_task FOREIGN KEY (task_id) REFERENCES diagnosis_task(task_id) ON DELETE CASCADE
);
