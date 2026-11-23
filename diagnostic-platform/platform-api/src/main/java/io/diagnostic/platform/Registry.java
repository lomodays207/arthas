package io.diagnostic.platform;

import io.diagnostic.protocol.Capability;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;
import java.util.stream.Collectors;

import static io.diagnostic.platform.AccessFilter.Role.*;
import static io.diagnostic.platform.Records.*;

@Service
class Registry {
    private static final long GRANT_LIMIT = Duration.ofHours(8).toMillis();

    private final Store store;
    private final Dispatch dispatch;

    private final SourcePreview sources;

    Registry(Store store, Dispatch dispatch, SourcePreview sources) {
        this.sources = sources;
        this.store = store;
        this.dispatch = dispatch;
    }

    @Transactional
    public Asset registerAsset(AccessFilter.Actor actor, AssetInput input) {
        actor.require(ADMIN);
        ensureZone(input.zoneId());
        store.write("""
                INSERT INTO asset_instance (asset_id, app_id, environment_name, zone_id, agent_id, display_name)
                VALUES (?, ?, ?, ?, ?, ?)
                """, input.assetId(), input.appId(), input.environmentName(), input.zoneId(),
                input.agentId(), input.displayName());
        store.write("INSERT INTO asset_policy (asset_id,paused,max_sessions,revision) VALUES (?,FALSE,16,1)", input.assetId());
        input.members().stream().distinct().forEach(member -> store.write(
                "INSERT INTO asset_member (asset_id, actor_id) VALUES (?, ?)", input.assetId(), member));
        store.audit(actor.id(), "ASSET_REGISTERED", null, null, null, input.assetId());
        return asset(input.assetId());
    }

    public List<Asset> assets(AccessFilter.Actor actor) {
        if (actor.role() == ADMIN || actor.role() == APPROVER) {
            return store.list(Asset.class, "SELECT * FROM asset_instance ORDER BY asset_id LIMIT 200");
        }
        actor.require(OPERATOR);
        return store.list(Asset.class, """
                SELECT a.* FROM asset_instance a
                JOIN asset_member m ON m.asset_id = a.asset_id
                WHERE m.actor_id = ? AND a.inventory_active=TRUE ORDER BY a.asset_id LIMIT 200
                """, actor.id());
    }

    @Transactional
    public Candidate registerTarget(AccessFilter.Actor actor, String assetId, TargetInput input) {
        actor.require(ADMIN);
        if (store.values(String.class,"SELECT asset_id FROM asset_instance WHERE asset_id=? AND inventory_active=TRUE FOR UPDATE",assetId).isEmpty())
            throw ApiError.missing();
        store.write("INSERT INTO jvm_target (target_id, asset_id, fingerprint, java_feature) VALUES (?, ?, ?, ?)",
                input.targetId(), assetId, input.fingerprint(), input.javaFeature());
        store.write("INSERT INTO target_control (target_id, generation, attach_state) VALUES (?, 0, 'RELEASED')",
                input.targetId());
        store.audit(actor.id(), "TARGET_REGISTERED", input.targetId(), null, null, null);
        return new Candidate(input.targetId(), input.javaFeature());
    }

    public List<Candidate> candidates(AccessFilter.Actor actor, String assetId) {
        asset(assetId);
        if (actor.role() != ADMIN && actor.role() != APPROVER) {
            actor.require(OPERATOR);
            requireMember(assetId, actor.id());
        }
        return store.list(Candidate.class, """
                SELECT target_id, java_feature FROM jvm_target
                WHERE asset_id = ? AND retired=FALSE ORDER BY target_id LIMIT 200
                """, assetId);
    }

    @Transactional
    public Grant requestGrant(AccessFilter.Actor actor, GrantInput input) {
        actor.require(OPERATOR);
        dispatch.lock(input.targetId());
        Target target = store.get(Target.class, "SELECT * FROM jvm_target WHERE target_id = ? AND retired=FALSE", input.targetId());
        requireMember(target.assetId(), actor.id());
        if (input.capabilities().contains(Capability.CODE_VIEW)) sources.requireEnabled(target.targetId());
        long now = store.now();
        if (input.requestedUntil() <= now || input.requestedUntil() > now + GRANT_LIMIT) {
            throw ApiError.invalid("INVALID_GRANT_DEADLINE");
        }
        
        String id = Store.id();
        String capabilities = input.capabilities().stream().map(Enum::name).sorted().collect(Collectors.joining(","));
        store.write("""
                INSERT INTO diagnosis_grant (grant_id, target_id, requester_id, capabilities, ticket_id,
                                             state, expires_at, revision)
                VALUES (?, ?, ?, ?, ?, 'PENDING', ?, 1)
                """, id, input.targetId(), actor.id(), capabilities, input.ticketId(), input.requestedUntil());
        store.audit(actor.id(), "GRANT_REQUESTED", input.targetId(), id, null, null);
        return grant(id);
    }

    public List<Grant> grants(AccessFilter.Actor actor) {
        if (actor.role() == APPROVER) {
            return store.list(Grant.class, "SELECT * FROM diagnosis_grant ORDER BY expires_at DESC, grant_id LIMIT 200");
        }
        actor.require(OPERATOR);
        return store.list(Grant.class, "SELECT * FROM diagnosis_grant WHERE requester_id = ? ORDER BY expires_at DESC, grant_id LIMIT 200", actor.id());
    }

    public Grant getGrant(AccessFilter.Actor actor, String grantId) {
        Grant grant = grant(grantId);
        if (actor.role() != APPROVER && !grant.requesterId().equals(actor.id())) {
            throw ApiError.forbidden();
        }
        return grant;
    }

    @Transactional
    public Grant decide(AccessFilter.Actor actor, String grantId, DecisionInput input) {
        actor.require(APPROVER);
        Grant initial = grant(grantId);
        Control control = dispatch.lock(initial.targetId());
        Grant grant = grant(grantId);
        var prior = store.find(DecisionRecord.class, "SELECT * FROM grant_decision WHERE event_id = ?", input.eventId());
        if (prior.isPresent()) {
            DecisionRecord recorded = prior.get();
            if (!recorded.grantId().equals(grantId) || !recorded.actorId().equals(actor.id())
                    || !recorded.decision().equals(input.decision().name())
                    || !recorded.reasonCode().equals(input.reasonCode())
                    || recorded.resultingRevision() != input.expectedRevision() + 1) {
                throw ApiError.conflict("DECISION_EVENT_REUSED");
            }
            return grant;
        }
        if (grant.revision() != input.expectedRevision()) {
            throw ApiError.conflict("GRANT_REVISION_CHANGED");
        }
        String next = switch (input.decision()) {
            case APPROVE -> {
                requirePending(grant);
                yield "GRANTED";
            }
            case DENY -> {
                requirePending(grant);
                yield "DENIED";
            }
            case REVOKE -> {
                if (!grant.state().equals("GRANTED")) {
                    throw ApiError.conflict("GRANT_STATE_CHANGED");
                }
                yield "REVOKED";
            }
        };
        long revision = grant.revision() + 1;
        store.write("UPDATE diagnosis_grant SET state = ?, revision = ? WHERE grant_id = ?", next, revision, grantId);
        store.write("""
                INSERT INTO grant_decision (event_id, grant_id, actor_id, decision, reason_code, resulting_revision)
                VALUES (?, ?, ?, ?, ?, ?)
                """, input.eventId(), grantId, actor.id(), input.decision().name(), input.reasonCode(), revision);
        store.audit(actor.id(), "GRANT_" + next, grant.targetId(), grantId, null, input.reasonCode());
        if (input.decision() == Decision.REVOKE) {
            dispatch.revoke(control, grantId);
        }
        return grant(grantId);
    }

    public List<Audit> audit(AccessFilter.Actor actor, String targetId) {
        actor.require(ADMIN);
        return store.list(Audit.class, """
                SELECT * FROM audit_event WHERE target_id = ?
                ORDER BY occurred_at DESC, event_id DESC LIMIT 200
                """, targetId);
    }

    void ensureZone(String zone) {
        store.write("INSERT INTO zone_policy(zone_id) VALUES (?) ON DUPLICATE KEY UPDATE zone_id=?",zone,zone);
    }

    private void requirePending(Grant grant) {
        if (!grant.state().equals("PENDING") || grant.expiresAt() <= store.now()) {
            throw ApiError.conflict("GRANT_STATE_CHANGED");
        }
    }

    private void requireMember(String assetId, String actorId) {
        int count = store.count(
                "SELECT COUNT(*) FROM asset_member WHERE asset_id = ? AND actor_id = ?",
                assetId, actorId);
        if (count == 0) {
            throw ApiError.forbidden();
        }
    }

    private Asset asset(String id) {
        return store.get(Asset.class, "SELECT * FROM asset_instance WHERE asset_id = ?", id);
    }

    private Grant grant(String id) {
        return store.get(Grant.class, "SELECT * FROM diagnosis_grant WHERE grant_id = ?", id);
    }
}
