package io.diagnostic.platform;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.diagnostic.protocol.TaskState;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

import static io.diagnostic.platform.AccessFilter.Role.EXECUTOR;
import static io.diagnostic.platform.Records.*;

@Service
class Deliveries {
    private static final long LEASE_TTL = Duration.ofSeconds(12).toMillis();
    private final Store store;
    private final Dispatch dispatch;
    private final ObjectMapper json;

    private record Receipt(String completion, String resultJson) {}

    Deliveries(Store store, Dispatch dispatch, ObjectMapper json) {
        this.store = store;
        this.dispatch = dispatch;
        this.json = json;
    }

    @Transactional
    public Delivery claim(AccessFilter.Actor actor) {
        actor.require(EXECUTOR);
        for (Operation candidate : store.list(Operation.class, """
                SELECT o.* FROM operation_outbox o WHERE o.agent_id = ? AND o.state = 'PENDING'
                AND o.available_at <= ?
                AND NOT EXISTS (
                    SELECT 1 FROM operation_outbox active
                    WHERE active.target_id = o.target_id AND active.state = 'CLAIMED'
                    AND active.lease_until > ?
                )
                ORDER BY o.target_id, o.available_at, o.created_at, o.operation_id LIMIT 20
                """, actor.id(), store.now(), store.now())) {
            dispatch.lock(candidate.targetId());
            dispatch.expire(candidate.targetId());
            Operation operation = operation(candidate.operationId());
            Control control = dispatch.lock(operation.targetId());
            if (!operation.state().equals("PENDING") || operation.generation() != control.generation()) {
                continue;
            }
            int active = store.count("""
                    SELECT COUNT(*) FROM operation_outbox WHERE target_id = ? AND state = 'CLAIMED'
                    """, operation.targetId());
            if (active > 0) {
                continue;
            }
            if (operation.operationType() == OperationType.ATTACH && dispatch.liveSessions(control) == 0) {
                discard(operation);
                dispatch.setAttachState(control.targetId(), control.generation(), "RELEASED");
                continue;
            }
            if (operation.operationType() == OperationType.RELEASE) {
                if (!control.attachState().equals("READY") || control.activeTaskId() != null
                        || dispatch.liveSessions(control) > 0) {
                    discard(operation);
                    continue;
                }
                dispatch.setAttachState(control.targetId(), control.generation(), "DRAINING");
            }
            if (operation.operationType() == OperationType.SNAPSHOT) {
                dispatch.transition(dispatch.task(operation.taskId()), TaskState.DISPATCHING);
            }
            Target target = store.get(Target.class, "SELECT * FROM jvm_target WHERE target_id = ?", operation.targetId());
            String token = Store.id();
            Long deadline = operation.operationType() == OperationType.SNAPSHOT
                    ? dispatch.task(operation.taskId()).deadlineAt() : null;
            long until = store.now() + LEASE_TTL;
            store.write("""
                    UPDATE operation_outbox SET state = 'CLAIMED', lease_token = ?, lease_until = ?
                    WHERE operation_id = ?
                    """, token, until, operation.operationId());
            store.audit(actor.id(), "OPERATION_CLAIMED", control.targetId(), null, operation.taskId(),
                    operation.operationType().name());
            return new Delivery(operation.operationId(), token, operation.targetId(), target.fingerprint(),
                    operation.generation(), operation.operationType(), operation.taskId(), until, deadline);
        }
        return null;
    }

    @Transactional
    public void complete(AccessFilter.Actor actor, String id, CompletionInput input) {
        actor.require(EXECUTOR);
        Operation initial = operation(id);
        if (!initial.agentId().equals(actor.id())) {
            throw ApiError.forbidden();
        }
        Control control = dispatch.lock(initial.targetId());
        Operation operation = operation(id);
        if (!input.leaseToken().equals(operation.leaseToken())) {
            throw ApiError.conflict("LEASE_CHANGED");
        }
        boolean requiresSnapshot = operation.operationType() == OperationType.SNAPSHOT
                && input.completion() == Completion.DONE;
        if (requiresSnapshot != (input.result() != null)) {
            throw ApiError.invalid("INVALID_RESULT");
        }
        if (requiresSnapshot && input.result().heapUsedBytes() > input.result().heapCommittedBytes()) {
            throw ApiError.invalid("INVALID_RESULT");
        }
        String result = serialize(input.result());
        var prior = store.find(Receipt.class, "SELECT * FROM edge_event_inbox WHERE operation_id = ?", id);
        if (prior.isPresent()) {
            if (!prior.get().completion().equals(input.completion().name())
                    || !Objects.equals(prior.get().resultJson(), result)) {
                throw ApiError.conflict("COMPLETION_CHANGED");
            }
            return;
        }
        if (operation.generation() != control.generation()
                || !List.of("CLAIMED", "UNCERTAIN").contains(operation.state())) {
            throw ApiError.conflict("OPERATION_STATE_CHANGED");
        }
        dispatch.expire(control.targetId());
        if (input.completion() == Completion.UNKNOWN) {
            boolean firstUnknown = operation(id).state().equals("CLAIMED");
            if (firstUnknown) {
                store.write("UPDATE operation_outbox SET lease_until = ? WHERE operation_id = ?", store.now(), id);
                dispatch.expire(control.targetId());
            }
            return;
        }
        switch (operation.operationType()) {
            case ATTACH -> completeAttach(control, input.completion());
            case RELEASE -> completeRelease(control, input.completion());
            case SNAPSHOT, CANCEL -> completeTask(operation, input.completion(), result);
        }
        store.write("""
                INSERT INTO edge_event_inbox (operation_id, completion, result_json, received_at)
                VALUES (?, ?, ?, ?)
                """, id, input.completion().name(), result, store.now());
        store.write("UPDATE operation_outbox SET state = 'ACKED' WHERE operation_id = ?", id);
        store.audit(actor.id(), "OPERATION_COMPLETED", control.targetId(), null, operation.taskId(),
                input.completion().name());
        dispatch.scheduleReleaseIfIdle(control.targetId());
    }

    private void completeAttach(Control control, Completion completion) {
        String next;
        String sessionState;
        switch (completion) {
            case ATTACHED -> {
                next = "READY";
                sessionState = "ACTIVE";
            }
            case FAILED -> {
                next = "RELEASED";
                sessionState = "CLOSED";
            }
            case TARGET_GONE -> {
                next = "TARGET_GONE";
                sessionState = "TARGET_GONE";
            }
            default -> throw ApiError.invalid("INVALID_ATTACHMENT_COMPLETION");
        }
        dispatch.setAttachState(control.targetId(), control.generation(), next);
        store.write("""
                UPDATE diagnosis_session SET state = ?
                WHERE target_id = ? AND generation = ? AND state = 'OPENING'
                """, sessionState, control.targetId(), control.generation());
    }

    private void completeRelease(Control control, Completion completion) {
        String state = switch (completion) {
            case RELEASED -> "RELEASED";
            case TARGET_GONE -> "TARGET_GONE";
            default -> throw ApiError.invalid("INVALID_RELEASE_COMPLETION");
        };
        dispatch.setAttachState(control.targetId(), control.generation(), state);
    }

    private void completeTask(Operation operation, Completion completion, String result) {
        boolean snapshot = operation.operationType() == OperationType.SNAPSHOT;
        if (snapshot && completion != Completion.DONE && completion != Completion.FAILED
                || !snapshot && completion != Completion.STOPPED) {
            throw ApiError.invalid("INVALID_TASK_COMPLETION");
        }
        Task task = dispatch.task(operation.taskId());
        if (List.of(TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED, TaskState.TIMED_OUT).contains(task.state())) {
            return;
        }
        if (task.cancelReason() != null || !snapshot) {
            dispatch.finish(task, "DEADLINE_EXCEEDED".equals(task.cancelReason())
                    ? TaskState.TIMED_OUT : TaskState.CANCELLED, null);
            return;
        }
        if (task.state() == TaskState.DISPATCHING && completion == Completion.DONE) {
            dispatch.transition(task, TaskState.RUNNING);
            task = dispatch.task(task.taskId());
        }
        dispatch.finish(task, completion == Completion.DONE ? TaskState.SUCCEEDED : TaskState.FAILED, result);
    }

    private Operation operation(String id) {
        return store.get(Operation.class, "SELECT * FROM operation_outbox WHERE operation_id = ?", id);
    }

    private void discard(Operation operation) {
        store.write("UPDATE operation_outbox SET state = 'SUPERSEDED' WHERE operation_id = ?", operation.operationId());
    }

    private String serialize(Snapshot snapshot) {
        if (snapshot == null) {
            return null;
        }
        try {
            return json.writeValueAsString(snapshot);
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Snapshot serialization failed", error);
        }
    }
}
