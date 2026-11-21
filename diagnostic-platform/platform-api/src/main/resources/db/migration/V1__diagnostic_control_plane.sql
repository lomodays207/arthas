CREATE TABLE asset_instance (
    asset_id VARCHAR(100) PRIMARY KEY,
    app_id VARCHAR(100) NOT NULL,
    environment_name VARCHAR(32) NOT NULL,
    zone_id VARCHAR(100) NOT NULL,
    agent_id VARCHAR(100) NOT NULL,
    display_name VARCHAR(160) NOT NULL
);

CREATE INDEX ix_assets_app_env ON asset_instance(app_id, environment_name);

CREATE TABLE asset_member (
    asset_id VARCHAR(100) NOT NULL,
    actor_id VARCHAR(100) NOT NULL,
    PRIMARY KEY (asset_id, actor_id),
    CONSTRAINT fk_member_asset FOREIGN KEY (asset_id) REFERENCES asset_instance(asset_id)
);

CREATE TABLE jvm_target (
    target_id VARCHAR(100) PRIMARY KEY,
    asset_id VARCHAR(100) NOT NULL,
    fingerprint VARCHAR(190) NOT NULL UNIQUE,
    java_feature INTEGER NOT NULL,
    CONSTRAINT fk_target_asset FOREIGN KEY (asset_id) REFERENCES asset_instance(asset_id)
);

CREATE TABLE diagnosis_grant (
    grant_id VARCHAR(36) PRIMARY KEY,
    target_id VARCHAR(100) NOT NULL,
    requester_id VARCHAR(100) NOT NULL,
    capabilities VARCHAR(240) NOT NULL,
    ticket_id VARCHAR(100) NOT NULL,
    state VARCHAR(20) NOT NULL,
    expires_at BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    CONSTRAINT fk_grant_target FOREIGN KEY (target_id) REFERENCES jvm_target(target_id)
);

CREATE INDEX ix_grants_expiry ON diagnosis_grant(state, expires_at);

CREATE TABLE grant_decision (
    event_id VARCHAR(100) PRIMARY KEY,
    grant_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(100) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    reason_code VARCHAR(100) NOT NULL,
    resulting_revision BIGINT NOT NULL,
    CONSTRAINT fk_decision_grant FOREIGN KEY (grant_id) REFERENCES diagnosis_grant(grant_id)
);

CREATE TABLE target_control (
    target_id VARCHAR(100) PRIMARY KEY,
    generation BIGINT NOT NULL,
    attach_state VARCHAR(24) NOT NULL,
    active_task_id VARCHAR(36),
    CONSTRAINT fk_control_target FOREIGN KEY (target_id) REFERENCES jvm_target(target_id)
);

CREATE TABLE diagnosis_session (
    session_id VARCHAR(36) PRIMARY KEY,
    target_id VARCHAR(100) NOT NULL,
    grant_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(100) NOT NULL,
    generation BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    state VARCHAR(20) NOT NULL,
    CONSTRAINT fk_session_target FOREIGN KEY (target_id) REFERENCES jvm_target(target_id),
    CONSTRAINT fk_session_grant FOREIGN KEY (grant_id) REFERENCES diagnosis_grant(grant_id)
);

CREATE INDEX ix_session_target ON diagnosis_session(target_id, generation, state, expires_at);
CREATE INDEX ix_session_grant ON diagnosis_session(grant_id, state);

CREATE TABLE diagnosis_task (
    task_id VARCHAR(36) PRIMARY KEY,
    session_id VARCHAR(36) NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    actor_id VARCHAR(100) NOT NULL,
    generation BIGINT NOT NULL,
    capability VARCHAR(40) NOT NULL,
    parameters VARCHAR(1000) NOT NULL,
    request_key VARCHAR(128) NOT NULL,
    state VARCHAR(24) NOT NULL,
    deadline_at BIGINT NOT NULL,
    cancel_reason VARCHAR(30),
    result_json VARCHAR(6000),
    UNIQUE (session_id, request_key),
    CONSTRAINT fk_task_session FOREIGN KEY (session_id) REFERENCES diagnosis_session(session_id)
);

CREATE INDEX ix_task_deadline ON diagnosis_task(state, deadline_at);

CREATE TABLE operation_outbox (
    operation_id VARCHAR(36) PRIMARY KEY,
    target_id VARCHAR(100) NOT NULL,
    agent_id VARCHAR(100) NOT NULL,
    generation BIGINT NOT NULL,
    operation_type VARCHAR(20) NOT NULL,
    task_id VARCHAR(36),
    created_at BIGINT NOT NULL,
    available_at BIGINT NOT NULL,
    lease_until BIGINT,
    lease_token VARCHAR(36),
    state VARCHAR(20) NOT NULL,
    CONSTRAINT fk_outbox_target FOREIGN KEY (target_id) REFERENCES jvm_target(target_id)
);

CREATE INDEX ix_operation_claim ON operation_outbox(agent_id, state, available_at);
CREATE INDEX ix_operation_target ON operation_outbox(target_id, state, created_at);

CREATE TABLE edge_event_inbox (
    operation_id VARCHAR(36) PRIMARY KEY,
    completion VARCHAR(24) NOT NULL,
    result_json VARCHAR(6000),
    received_at BIGINT NOT NULL,
    CONSTRAINT fk_event_operation FOREIGN KEY (operation_id) REFERENCES operation_outbox(operation_id)
);

CREATE TABLE audit_event (
    event_id VARCHAR(36) PRIMARY KEY,
    actor_id VARCHAR(100) NOT NULL,
    action VARCHAR(48) NOT NULL,
    target_id VARCHAR(100),
    grant_id VARCHAR(36),
    task_id VARCHAR(36),
    reason_code VARCHAR(100),
    occurred_at BIGINT NOT NULL
);

CREATE INDEX ix_audit_target ON audit_event(target_id, occurred_at);
