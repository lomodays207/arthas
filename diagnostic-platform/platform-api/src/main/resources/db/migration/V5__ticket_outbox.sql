CREATE TABLE ticket_outbox (
    sequence_no BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(36) NOT NULL UNIQUE,
    event_type VARCHAR(32) NOT NULL,
    reference_id VARCHAR(36) NOT NULL,
    ticket_id VARCHAR(100) NOT NULL,
    occurred_at BIGINT NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX ix_ticket_pending ON ticket_outbox(acknowledged,sequence_no);
