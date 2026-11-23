CREATE TABLE task_event (
    task_id VARCHAR(36) NOT NULL,
    sequence_no BIGINT NOT NULL,
    state VARCHAR(24) NOT NULL,
    occurred_at BIGINT NOT NULL,
    PRIMARY KEY (task_id, sequence_no),
    CONSTRAINT fk_task_event_task FOREIGN KEY (task_id) REFERENCES diagnosis_task(task_id) ON DELETE CASCADE
);
INSERT INTO task_event (task_id, sequence_no, state, occurred_at)
SELECT task_id, 1, state, 0 FROM diagnosis_task;
