package io.diagnostic.protocol;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TaskStateTest {
    @Test
    void runningTaskRequiresCancellationBeforeConfirmedTimeout() {
        assertFalse(TaskState.RUNNING.canTransitionTo(TaskState.TIMED_OUT));
        assertTrue(TaskState.RUNNING.canTransitionTo(TaskState.CANCEL_REQUESTED));
        assertTrue(TaskState.CANCEL_REQUESTED.canTransitionTo(TaskState.TIMED_OUT));
    }

    @Test
    void terminatedTaskCannotBeReopenedByLateResults() {
        assertFalse(TaskState.CANCELLED.canTransitionTo(TaskState.RUNNING));
        assertFalse(TaskState.TIMED_OUT.canTransitionTo(TaskState.SUCCEEDED));
    }
}
