package io.diagnostic.protocol;

public enum TaskState {
    QUEUED,
    DISPATCHING,
    RUNNING,
    CANCEL_REQUESTED,
    RECONCILING,
    SUCCEEDED,
    FAILED,
    CANCELLED,
    TIMED_OUT;

    public boolean canTransitionTo(TaskState next) {
        return switch (this) {
            case QUEUED -> next == DISPATCHING || next == CANCELLED || next == TIMED_OUT;
            case DISPATCHING -> next == RUNNING || next == FAILED
                    || next == CANCEL_REQUESTED || next == RECONCILING;
            case RUNNING -> next == SUCCEEDED || next == FAILED
                    || next == CANCEL_REQUESTED || next == RECONCILING;
            case CANCEL_REQUESTED -> next == CANCELLED || next == TIMED_OUT || next == RECONCILING;
            case RECONCILING -> next == RUNNING || next == CANCEL_REQUESTED
                    || next == CANCELLED || next == TIMED_OUT || next == FAILED || next == SUCCEEDED;
            case SUCCEEDED, FAILED, CANCELLED, TIMED_OUT -> false;
        };
    }
}
