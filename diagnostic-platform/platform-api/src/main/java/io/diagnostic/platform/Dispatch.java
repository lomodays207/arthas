package io.diagnostic.platform;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.diagnostic.protocol.Capability;
import io.diagnostic.protocol.TaskState;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;

import static io.diagnostic.platform.AccessFilter.Role.OPERATOR;
import static io.diagnostic.platform.Records.*;

@Service
class Dispatch {
    private static final long SESSION_TTL = Duration.ofSeconds(45).toMillis();
    private static final long TASK_TTL = Duration.ofSeconds(20).toMillis();

    private final Store store;
    private final ObjectMapper json;
    private final long idleTtl;

    private final SourcePreview sources;

    Dispatch(Store store, ObjectMapper json, SourcePreview sources, @Value("${diagnostic.idle-release-ms:120000}") long idleTtl) {
        if (idleTtl < 100 || idleTtl > Duration.ofHours(1).toMillis()) {
            throw new IllegalArgumentException("Invalid idle release duration");
        }
        this.sources = sources;
        this.store = store;
        this.json = json;
        this.idleTtl = idleTtl;
    }

    @Transactional
    public Session open(AccessFilter.Actor actor, OpenInput input) {
        actor.require(OPERATOR);
        Control control = lock(input.targetId());
        Grant grant = requireGrant(actor.id(), input.targetId(), input.grantId());
        if (!List.of("RELEASED", "ATTACHING", "READY").contains(control.attachState())) {
            throw ApiError.conflict("ATTACHMENT_UNAVAILABLE");
        }
        Operations.Policy policy = policy(input.targetId());
        if (liveSessions(control) >= policy.maxSessions()) throw ApiError.conflict("SESSION_QUOTA");
        long generation = control.generation();
        if (control.attachState().equals("RELEASED")) {
            generation++;
            store.write("""
                    UPDATE target_control SET generation = ?, attach_state = 'ATTACHING'
                    WHERE target_id = ?
                    """, generation, control.targetId());
            enqueue(control.targetId(), generation, OperationType.ATTACH, null, store.now());
        } else {
            discardPending(control.targetId(), control.generation(), OperationType.RELEASE, null);
        }
        String id = Store.id();
        String state = control.attachState().equals("READY") ? "ACTIVE" : "OPENING";
        store.write("""
                INSERT INTO diagnosis_session (session_id, target_id, grant_id, actor_id, generation,
                                               expires_at, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, id, control.targetId(), grant.grantId(), actor.id(), generation, expiry(grant), state);
        store.audit(actor.id(), "SESSION_OPENED", control.targetId(), grant.grantId(), null, null);
        return session(id);
    }

    public Session lookupSession(AccessFilter.Actor actor, String id) {
        return ownedSession(actor, id);
    }

    @Transactional
    public Session heartbeat(AccessFilter.Actor actor, String id) {
        Session initial = ownedSession(actor, id);
        lock(initial.targetId());
        Session current = ownedSession(actor, id);
        requireActiveOrOpening(current);
        Grant grant = requireGrant(actor.id(), current.targetId(), current.grantId());
        store.write("UPDATE diagnosis_session SET expires_at = ? WHERE session_id = ?", expiry(grant), id);
        return session(id);
    }

    @Transactional
    public Session close(AccessFilter.Actor actor, String id) {
        Session initial = ownedSession(actor, id);
        Control control = lock(initial.targetId());
        Session current = ownedSession(actor, id);
        closeSession(current, "CLOSED", actor.id());
        scheduleReleaseIfIdle(control.targetId());
        return session(id);
    }

    @Transactional
    public TaskView submit(AccessFilter.Actor actor, String sessionId, String key, TaskInput input) {
        if (key == null || !key.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw ApiError.invalid("INVALID_IDEMPOTENCY_KEY");
        }
        input.validate();
        String parameters = input.criteria() == null ? "{}" : encode(input.criteria());
        Session initial = ownedSession(actor, sessionId);
        Control control = lock(initial.targetId());
        Session current = ownedSession(actor, sessionId);
        Grant grant = requireGrant(actor.id(), current.targetId(), current.grantId());
        requireActiveOrOpening(current);
        if (input.capability()==Capability.CODE_VIEW) sources.requireEnabled(current.targetId());
        if (!List.of(grant.capabilities().split(",")).contains(input.capability().name())) {
            throw ApiError.forbidden();
        }
        var existing = store.find(Task.class, """
                SELECT * FROM diagnosis_task WHERE session_id = ? AND request_key = ?
                """, sessionId, key);
        if (existing.isPresent()) {
            if (existing.get().capability() != input.capability() || !existing.get().parameters().equals(parameters)) {
                throw ApiError.conflict("IDEMPOTENCY_KEY_REUSED");
            }
            return view(existing.get());
        }
        if (!current.state().equals("ACTIVE") || !control.attachState().equals("READY")
                || current.generation() != control.generation()) {
            throw ApiError.conflict("SESSION_NOT_READY");
        }
        policy(control.targetId());
        if (control.activeTaskId() != null) {
            throw ApiError.conflict("TARGET_BUSY");
        }
        String id = Store.id();
        long deadline = Math.min(Math.min(grant.expiresAt(), current.expiresAt()), store.now() + TASK_TTL);
        store.write("""
                INSERT INTO diagnosis_task (task_id, session_id, target_id, actor_id, generation, capability,
                                            parameters, request_key, state, deadline_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'QUEUED', ?)
                """, id, sessionId, current.targetId(), actor.id(), current.generation(), input.capability().name(),
                parameters, key, deadline);
        store.write("UPDATE target_control SET active_task_id = ? WHERE target_id = ?", id, current.targetId());
        appendEvent(id, TaskState.QUEUED);
        enqueue(current.targetId(), current.generation(), OperationType.SNAPSHOT, id, store.now());
        store.audit(actor.id(), "TASK_QUEUED", current.targetId(), current.grantId(), id, null);
        return view(task(id));
    }

    record Overview(long generation,Long receivedAt,boolean stale,boolean pending,Snapshot result) {}
    record Cached(String resultJson,long receivedAt) {}

    @Transactional
    public Overview overview(AccessFilter.Actor actor,String id,boolean refresh) {
        Session initial=ownedSession(actor,id);
        Control control=lock(initial.targetId());
        Session session=ownedSession(actor,id);
        requireActiveOrOpening(session);
        var grant=requireGrant(actor.id(),session.targetId(),session.grantId());
        if (!List.of(grant.capabilities().split(",")).contains(Capability.JVM_OVERVIEW.name())) throw ApiError.forbidden();
        if (!session.state().equals("ACTIVE") || session.generation()!=control.generation()) throw ApiError.conflict("SESSION_NOT_READY");
        var cached=store.find(Cached.class,"""
                SELECT t.result_json,e.occurred_at received_at FROM diagnosis_task t
                JOIN task_event e ON t.task_id=e.task_id AND e.state='SUCCEEDED'
                WHERE t.target_id=? AND t.generation=? AND t.capability='JVM_OVERVIEW' AND t.state='SUCCEEDED'
                ORDER BY e.occurred_at DESC,t.task_id DESC LIMIT 1
                """,session.targetId(),control.generation());
        boolean stale=cached.isEmpty() || cached.get().receivedAt()+5000 <= store.now();
        boolean pending=control.activeTaskId()!=null && task(control.activeTaskId()).capability()==Capability.JVM_OVERVIEW;
        if (refresh && stale && !pending) {
            submit(actor,id,Store.id(),new TaskInput(Capability.JVM_OVERVIEW,null));
            pending=true;
        }
        if (cached.isEmpty()) return new Overview(control.generation(),null,true,pending,null);
        try {
            var value=cached.get();
            return new Overview(control.generation(),value.receivedAt(),stale,pending,json.readValue(value.resultJson(),Snapshot.class));
        } catch (JsonProcessingException e) { throw new IllegalStateException(e); }
    }

    private Operations.Policy policy(String target) {
        var policy = store.get(Operations.Policy.class, """
                SELECT p.asset_id,(p.paused OR z.paused) paused,p.max_sessions,p.revision
                FROM asset_policy p JOIN jvm_target t ON p.asset_id=t.asset_id
                JOIN asset_instance a ON a.asset_id=p.asset_id JOIN zone_policy z ON z.zone_id=a.zone_id
                WHERE t.target_id=? FOR UPDATE
                """,target);
        if (policy.paused()) throw ApiError.conflict("ASSET_PAUSED");
        return policy;
    }

    public TaskView lookupTask(AccessFilter.Actor actor, String id) {
        Task task = ownedTask(actor, id);
        Session session = session(task.sessionId());
        requireGrant(actor.id(), task.targetId(), session.grantId());
        return view(task);
    }

    @Transactional
    public TaskView cancel(AccessFilter.Actor actor, String id) {
        Task initial = ownedTask(actor, id);
        lock(initial.targetId());
        Task task = ownedTask(actor, id);
        cancelTask(task, "USER_CANCELLED", actor.id());
        scheduleReleaseIfIdle(task.targetId());
        Task current = task(id);
        Session session = session(current.sessionId());
        if (!canReadGrant(actor.id(), current.targetId(), session.grantId())) {
            return new TaskView(current.taskId(), current.targetId(), current.capability(), current.state(),
                    current.generation(), current.deadlineAt(), null, null);
        }
        return view(current);
    }

    void revoke(Control control, String grantId) {
        for (Session session : store.list(Session.class, """
                SELECT * FROM diagnosis_session WHERE grant_id = ? AND state IN ('ACTIVE','OPENING')
                """, grantId)) {
            closeSession(session, "REVOKED", "system");
        }
        scheduleReleaseIfIdle(control.targetId());
    }

    @Scheduled(fixedDelayString = "${diagnostic.sweep-delay-ms:1000}")
    @Transactional
    public void sweep() {
        List<String> targets = store.values(String.class, """
                SELECT target_id FROM (
                    SELECT target_id FROM diagnosis_session
                    WHERE state IN ('ACTIVE','OPENING') AND expires_at <= ?
                    UNION
                    SELECT target_id FROM diagnosis_task
                    WHERE state IN ('QUEUED','DISPATCHING','RUNNING') AND deadline_at <= ?
                    UNION
                    SELECT target_id FROM diagnosis_grant
                    WHERE state IN ('GRANTED','PENDING') AND expires_at <= ?
                    UNION
                    SELECT target_id FROM operation_outbox
                    WHERE state = 'CLAIMED' AND lease_until <= ?
                ) due ORDER BY target_id LIMIT 100
                """, store.now(), store.now(), store.now(), store.now());
        for (String target : targets) {
            lock(target);
            expire(target);
        }
    }

    void expire(String target) {
        long now = store.now();
        for (Grant grant : store.list(Grant.class, """
                SELECT * FROM diagnosis_grant WHERE target_id = ? AND state IN ('GRANTED','PENDING') AND expires_at <= ?
                """, target, now)) {
            store.write("UPDATE diagnosis_grant SET state = 'EXPIRED', revision = revision + 1 WHERE grant_id = ?",
                    grant.grantId());
            store.audit("system", "GRANT_EXPIRED", target, grant.grantId(), null, null);
        }
        for (Session session : store.list(Session.class, """
                SELECT * FROM diagnosis_session WHERE target_id = ? AND state IN ('ACTIVE','OPENING') AND expires_at <= ?
                """, target, now)) {
            closeSession(session, "EXPIRED", "system");
        }
        for (Task task : store.list(Task.class, """
                SELECT * FROM diagnosis_task WHERE target_id = ? AND state IN ('QUEUED','DISPATCHING','RUNNING') AND deadline_at <= ?
                """, target, now)) {
            cancelTask(task, "DEADLINE_EXCEEDED", "system");
        }
        for (Operation operation : store.list(Operation.class, """
                SELECT * FROM operation_outbox WHERE target_id = ? AND state = 'CLAIMED' AND lease_until <= ?
                """, target, now)) {
            store.write("UPDATE operation_outbox SET state = 'UNCERTAIN' WHERE operation_id = ?", operation.operationId());
            switch (operation.operationType()) {
                case ATTACH, RELEASE -> setAttachState(target, operation.generation(), "RECONCILING");
                case SNAPSHOT, CANCEL -> {
                    Task task = task(operation.taskId());
                    if (task.state() == TaskState.DISPATCHING || task.state() == TaskState.CANCEL_REQUESTED) {
                        transition(task, TaskState.RECONCILING);
                    }
                }
            }
            store.audit("system", "OPERATION_UNCERTAIN", target, null, operation.taskId(), operation.operationType().name());
        }
        scheduleReleaseIfIdle(target);
    }

    Control lock(String target) {
        return store.get(Control.class, "SELECT * FROM target_control WHERE target_id = ? FOR UPDATE", target);
    }

    Session session(String id) {
        return store.get(Session.class, "SELECT * FROM diagnosis_session WHERE session_id = ?", id);
    }

    Task task(String id) {
        return store.get(Task.class, "SELECT * FROM diagnosis_task WHERE task_id = ?", id);
    }

    void enqueue(String target, long generation, OperationType type, String task, long availableAt) {
        store.write("""
                INSERT INTO operation_outbox (operation_id, target_id, agent_id, generation,
                                              operation_type, task_id, created_at, available_at, state)
                SELECT ?, t.target_id, a.agent_id, ?, ?, ?, ?, ?, 'PENDING'
                FROM jvm_target t JOIN asset_instance a ON t.asset_id = a.asset_id WHERE t.target_id = ?
                """, Store.id(), generation, type.name(), task, store.now(), availableAt, target);
    }

    void discardPending(String target, long generation, OperationType type, String task) {
        if (task == null) {
            store.write("""
                    UPDATE operation_outbox SET state = 'SUPERSEDED'
                    WHERE target_id = ? AND generation = ? AND operation_type = ? AND task_id IS NULL AND state = 'PENDING'
                    """, target, generation, type.name());
        } else {
            store.write("""
                    UPDATE operation_outbox SET state = 'SUPERSEDED'
                    WHERE target_id = ? AND generation = ? AND operation_type = ? AND task_id = ? AND state = 'PENDING'
                    """, target, generation, type.name(), task);
        }
    }

    void setAttachState(String target, long generation, String state) {
        store.write("UPDATE target_control SET attach_state = ? WHERE target_id = ? AND generation = ?",
                state, target, generation);
    }

    void transition(Task task, TaskState next) {
        if (!task.state().canTransitionTo(next)) {
            throw ApiError.conflict("TASK_STATE_CHANGED");
        }
        store.write("UPDATE diagnosis_task SET state = ? WHERE task_id = ?", next.name(), task.taskId());
        appendEvent(task.taskId(), next);
    }

    record TaskEvent(long sequenceNo, String state, long occurredAt) {}

    private void appendEvent(String id, TaskState state) {
        // All writers already hold the target lock.
        long next = store.values(Long.class, "SELECT COALESCE(MAX(sequence_no),0) + 1 FROM task_event WHERE task_id=?", id).get(0);
        store.write("INSERT INTO task_event(task_id,sequence_no,state,occurred_at) VALUES (?,?,?,?)",
                id, next, state.name(), store.now());
    }

    @Transactional(readOnly = true)
    public List<TaskEvent> events(AccessFilter.Actor actor, String id, long after) {
        lookupTask(actor,id);
        return store.list(TaskEvent.class, "SELECT sequence_no,state,occurred_at FROM task_event WHERE task_id=? AND sequence_no>? ORDER BY sequence_no LIMIT 32",id,after);
    }

    void finish(Task task, TaskState next, String result) {
        transition(task, next);
        store.write("UPDATE diagnosis_task SET result_json = ? WHERE task_id = ?", result, task.taskId());
        store.write("UPDATE target_control SET active_task_id = NULL WHERE target_id = ? AND active_task_id = ?",
                task.targetId(), task.taskId());
        discardPending(task.targetId(), task.generation(), OperationType.CANCEL, task.taskId());
    }

    void scheduleReleaseIfIdle(String target) {
        Control control = store.get(Control.class, "SELECT * FROM target_control WHERE target_id = ?", target);
        if (control.activeTaskId() != null || !control.attachState().equals("READY") || liveSessions(control) > 0) {
            return;
        }
        int pending = store.count("""
                SELECT COUNT(*) FROM operation_outbox
                WHERE target_id = ? AND generation = ? AND operation_type = 'RELEASE' AND state = 'PENDING'
                """, target, control.generation());
        if (pending == 0) {
            enqueue(target, control.generation(), OperationType.RELEASE, null, store.now() + idleTtl);
        }
    }

    int liveSessions(Control control) {
        int count = store.count("""
                SELECT COUNT(*) FROM diagnosis_session WHERE target_id = ? AND generation = ?
                AND state IN ('ACTIVE','OPENING') AND expires_at > ?
                """, control.targetId(), control.generation(), store.now());
        return count;
    }

    private void closeSession(Session session, String state, String actor) {
        if (!List.of("ACTIVE", "OPENING").contains(session.state())) {
            return;
        }
        store.write("UPDATE diagnosis_session SET state = ? WHERE session_id = ?", state, session.sessionId());
        for (Task task : store.list(Task.class, """
                SELECT * FROM diagnosis_task WHERE session_id = ? AND state IN ('QUEUED','DISPATCHING','RUNNING','RECONCILING')
                """, session.sessionId())) {
            cancelTask(task, "SESSION_" + state, actor);
        }
        store.audit(actor, "SESSION_" + state, session.targetId(), session.grantId(), null, null);
    }

    private void cancelTask(Task task, String reason, String actor) {
        if (task.state() == TaskState.QUEUED) {
            discardPending(task.targetId(), task.generation(), OperationType.SNAPSHOT, task.taskId());
            finish(task, reason.equals("DEADLINE_EXCEEDED") ? TaskState.TIMED_OUT : TaskState.CANCELLED, null);
        } else if (List.of(TaskState.DISPATCHING, TaskState.RUNNING, TaskState.RECONCILING).contains(task.state())
                && task.cancelReason() == null) {
            transition(task, TaskState.CANCEL_REQUESTED);
            store.write("UPDATE diagnosis_task SET cancel_reason = ? WHERE task_id = ?", reason, task.taskId());
            enqueue(task.targetId(), task.generation(), OperationType.CANCEL, task.taskId(), store.now());
        } else {
            return;
        }
        store.audit(actor, "TASK_CANCEL_INTENT", task.targetId(), null, task.taskId(), reason);
    }

    private Session ownedSession(AccessFilter.Actor actor, String id) {
        actor.require(OPERATOR);
        Session session = session(id);
        if (!session.actorId().equals(actor.id())) {
            throw ApiError.forbidden();
        }
        return session;
    }

    private Task ownedTask(AccessFilter.Actor actor, String id) {
        actor.require(OPERATOR);
        Task task = task(id);
        if (!task.actorId().equals(actor.id())) {
            throw ApiError.forbidden();
        }
        return task;
    }

    private void requireActiveOrOpening(Session session) {
        if (!List.of("ACTIVE", "OPENING").contains(session.state()) || session.expiresAt() <= store.now()) {
            throw ApiError.conflict("SESSION_INACTIVE");
        }
    }

    private Grant requireGrant(String actor, String target, String id) {
        Grant grant = store.get(Grant.class, "SELECT * FROM diagnosis_grant WHERE grant_id = ?", id);
        if (!grant.requesterId().equals(actor) || !grant.targetId().equals(target)
                || !grant.state().equals("GRANTED") || grant.expiresAt() <= store.now()) {
            throw ApiError.forbidden();
        }
        return grant;
    }

    private boolean canReadGrant(String actor, String target, String grantId) {
        try {
            requireGrant(actor, target, grantId);
            return true;
        } catch (ApiError denied) {
            return false;
        }
    }

    private long expiry(Grant grant) {
        return Math.min(grant.expiresAt(), store.now() + SESSION_TTL);
    }

    String encode(Object value) {
        try { return json.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalStateException(e); }
    }

    Criteria criteria(Task task) {
        if (task.parameters().equals("{}")) return null;
        try { return json.readValue(task.parameters(), Criteria.class); }
        catch (JsonProcessingException e) { throw new IllegalStateException(e); }
    }

    TaskView view(Task task) {
        try {
            boolean overview = task.capability() == Capability.JVM_OVERVIEW;
            Snapshot result = overview && task.resultJson() != null ? json.readValue(task.resultJson(), Snapshot.class) : null;
            Evidence evidence = !overview && task.resultJson() != null ? json.readValue(task.resultJson(), Evidence.class) : null;
            return new TaskView(task.taskId(), task.targetId(), task.capability(), task.state(),
                    task.generation(), task.deadlineAt(), result, evidence);
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Persisted snapshot cannot be read", error);
        }
    }
}
