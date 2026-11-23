package io.diagnostic.platform;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import java.util.List;

import static io.diagnostic.platform.AccessFilter.*;
import static io.diagnostic.platform.AccessFilter.Role.*;

@RestController
@RequestMapping("/api/v1")
class Operations {
    record Policy(String assetId,boolean paused,int maxSessions,long revision) {}
    record Change(@NotNull Boolean paused,@Min(1) @Max(128) int maxSessions,@Positive long expectedRevision) {}
    record Channel(String agentId,long lastSeen,boolean online) {}
    record Cleanup(String targetId,long generation,String attachState,String activeTaskId) {}
    record Share(@NotBlank @Pattern(regexp=Records.KEY) String readerId,@Positive long expiresAt) {}
    record Reference(String referenceId,String taskId,String ownerId,String readerId,long expiresAt,boolean revoked) {}
    private final Store store;
    private final Dispatch dispatch;
    Operations(Store store,Dispatch dispatch) { this.store=store; this.dispatch=dispatch; }

    record Zone(String zoneId,boolean paused,long revision) {}
    record ZoneChange(@NotNull Boolean paused,@Positive long expectedRevision) {}

    @GetMapping("/management/zones")
    List<Zone> zones(@RequestAttribute(ACTOR) Actor actor) {
        actor.require(ADMIN);
        return store.list(Zone.class,"SELECT * FROM zone_policy ORDER BY zone_id LIMIT 200");
    }

    @PutMapping("/management/zones/{id}") @Transactional
    Zone zone(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id,@Valid @RequestBody ZoneChange change) {
        actor.require(ADMIN);
        if (store.write("UPDATE zone_policy SET paused=?,revision=revision+1 WHERE zone_id=? AND revision=?",
                change.paused(),id,change.expectedRevision())!=1) throw ApiError.conflict("ZONE_REVISION_CHANGED");
        store.audit(actor.id(),"ZONE_POLICY_CHANGED",null,null,null,id);
        return store.get(Zone.class,"SELECT * FROM zone_policy WHERE zone_id=?",id);
    }

    @GetMapping("/management/channels")
    List<Channel> channels(@RequestAttribute(ACTOR) Actor actor) {
        actor.require(ADMIN);
        return store.list(Channel.class,"""
                SELECT a.agent_id,COALESCE(c.last_seen,0) last_seen,
                  CASE WHEN c.last_seen >= ? THEN TRUE ELSE FALSE END online
                FROM (SELECT DISTINCT agent_id FROM asset_instance) a LEFT JOIN agent_channel c ON a.agent_id=c.agent_id
                ORDER BY a.agent_id LIMIT 200
                """,store.now()-15000);
    }

    @GetMapping("/targets/{id}/control")
    Records.Control control(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id) {
        if (actor.role()!=ADMIN) actor.require(RESPONDER);
        return store.get(Records.Control.class,"SELECT * FROM target_control WHERE target_id=?",id);
    }

    @GetMapping("/management/cleanup")
    List<Cleanup> cleanup(@RequestAttribute(ACTOR) Actor actor) {
        actor.require(ADMIN);
        return store.list(Cleanup.class,"""
                SELECT c.* FROM target_control c LEFT JOIN diagnosis_task t ON t.task_id=c.active_task_id
                WHERE c.attach_state IN ('RECONCILING','DRAINING') OR t.state='RECONCILING'
                ORDER BY c.target_id LIMIT 200
                """);
    }

    @GetMapping("/assets/{id}/policy")
    Policy policy(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id) {
        actor.require(ADMIN);
        return store.get(Policy.class,"SELECT * FROM asset_policy WHERE asset_id=?",id);
    }

    @PutMapping("/assets/{id}/policy") @Transactional
    Policy update(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id,@Valid @RequestBody Change change) {
        actor.require(ADMIN);
        if (store.write("""
                UPDATE asset_policy SET paused=?,max_sessions=?,revision=revision+1 WHERE asset_id=? AND revision=?
                """,change.paused(),change.maxSessions(),id,change.expectedRevision())!=1)
            throw ApiError.conflict("POLICY_REVISION_CHANGED");
        store.audit(actor.id(),"ASSET_POLICY_CHANGED",null,null,null,id);
        return policy(actor,id);
    }

    @PostMapping("/tasks/{id}/references") @Transactional
    Reference share(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id,@Valid @RequestBody Share share) {
        Records.Task task=dispatch.task(id);
        dispatch.lock(task.targetId());
        var view=dispatch.lookupTask(actor,id);
        if (view.result()==null && view.evidence()==null) throw ApiError.conflict("NO_EVIDENCE");
        var session=dispatch.session(task.sessionId());
        var grant=store.get(Records.Grant.class,"SELECT * FROM diagnosis_grant WHERE grant_id=?",session.grantId());
        if (share.expiresAt()<=store.now() || share.expiresAt()>grant.expiresAt()) throw ApiError.invalid("INVALID_EXPIRY");
        if (store.count("""
                SELECT COUNT(*) FROM asset_member m JOIN jvm_target t ON t.asset_id=m.asset_id
                WHERE t.target_id=? AND m.actor_id=?
                """,task.targetId(),share.readerId())!=1) throw ApiError.forbidden();
        String ref=Store.id();
        store.write("INSERT INTO evidence_reference VALUES (?,?,?,?,?,FALSE)",ref,id,actor.id(),share.readerId(),share.expiresAt());
        ticketEvent("REFERENCE_SHARED",ref,grant.ticketId());
        store.audit(actor.id(),"EVIDENCE_SHARED",task.targetId(),session.grantId(),id,share.readerId());
        return reference(ref);
    }

    @GetMapping("/references/{id}") @Transactional
    Records.TaskView read(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id) {
        actor.require(OPERATOR);
        Reference ref=reference(id);
        if (!ref.readerId().equals(actor.id()) || ref.revoked() || ref.expiresAt()<=store.now()) throw ApiError.forbidden();
        var task=dispatch.task(ref.taskId());
        var session=dispatch.session(task.sessionId());
        var owner=store.get(Records.Grant.class,"SELECT * FROM diagnosis_grant WHERE grant_id=?",session.grantId());
        if (!owner.state().equals("GRANTED") || owner.expiresAt()<=store.now()) throw ApiError.forbidden();
        boolean allowed=store.values(String.class,"""
                SELECT g.capabilities FROM diagnosis_grant g JOIN jvm_target t ON t.target_id=g.target_id
                JOIN asset_member m ON m.asset_id=t.asset_id AND m.actor_id=g.requester_id
                WHERE g.target_id=? AND g.requester_id=? AND g.state='GRANTED' AND g.expires_at>?
                """,task.targetId(),actor.id(),store.now()).stream().anyMatch(c -> List.of(c.split(",")).contains(task.capability().name()));
        if (!allowed) throw ApiError.forbidden();
        store.audit(actor.id(),"EVIDENCE_READ",task.targetId(),owner.grantId(),task.taskId(),null);
        return dispatch.view(task);
    }

    @DeleteMapping("/references/{id}") @Transactional
    void revoke(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id) {
        Reference ref=reference(id);
        if (actor.role()!=ADMIN && !ref.ownerId().equals(actor.id())) throw ApiError.forbidden();
        if (store.write("UPDATE evidence_reference SET revoked=TRUE WHERE reference_id=? AND revoked=FALSE",id)==1) {
            var task=dispatch.task(ref.taskId());
            var session=dispatch.session(task.sessionId());
            var grant=store.get(Records.Grant.class,"SELECT * FROM diagnosis_grant WHERE grant_id=?",session.grantId());
            ticketEvent("REFERENCE_REVOKED",id,grant.ticketId());
            store.audit(actor.id(),"EVIDENCE_REVOKED",task.targetId(),null,task.taskId(),null);
        }
    }

    record TicketEvent(long sequenceNo,String eventId,String eventType,String referenceId,String ticketId,long occurredAt) {}

    private void ticketEvent(String type,String ref,String ticket) {
        store.write("""
                INSERT INTO ticket_outbox(event_id,event_type,reference_id,ticket_id,occurred_at)
                VALUES (?,?,?,?,?)
                """,Store.id(),type,ref,ticket,store.now());
    }

    @GetMapping("/integrations/tickets/events")
    List<TicketEvent> outstanding(@RequestAttribute(ACTOR) Actor actor) {
        actor.require(INTEGRATION);
        return store.list(TicketEvent.class,"SELECT * FROM ticket_outbox WHERE acknowledged=FALSE ORDER BY sequence_no LIMIT 100");
    }

    @PostMapping("/integrations/tickets/events/{id}/ack") @Transactional
    void acknowledge(@RequestAttribute(ACTOR) Actor actor,@PathVariable String id) {
        actor.require(INTEGRATION);
        if (store.count("SELECT COUNT(*) FROM ticket_outbox WHERE event_id=?",id)==0) throw ApiError.missing();
        store.write("UPDATE ticket_outbox SET acknowledged=TRUE WHERE event_id=?",id);
    }

    private Reference reference(String id) {
        return store.get(Reference.class,"SELECT * FROM evidence_reference WHERE reference_id=?",id);
    }
}
