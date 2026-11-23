package io.diagnostic.platform;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@RestController
@RequestMapping("/api/v1/inventory/assets")
class Inventory {
    record Change(@Positive long sourceRevision,@NotNull Boolean active,@Valid @NotNull Records.AssetInput asset) {}
    record Status(String assetId,boolean inventoryActive,long sourceRevision,String sourceDigest) {}
    private final Store store;
    private final Registry registry;
    private final Dispatch dispatch;
    Inventory(Store store,Registry registry,Dispatch dispatch) {
        this.store=store; this.registry=registry; this.dispatch=dispatch;
    }

    @GetMapping("/{id}")
    Status get(@RequestAttribute(AccessFilter.ACTOR) AccessFilter.Actor actor,@PathVariable String id) {
        actor.require(AccessFilter.Role.ADMIN);
        return store.get(Status.class,"SELECT * FROM asset_instance WHERE asset_id=?",id);
    }

    @PutMapping("/{id}") @Transactional
    Status sync(@RequestAttribute(AccessFilter.ACTOR) AccessFilter.Actor actor,@PathVariable String id,
                @Valid @RequestBody Change change) throws Exception {
        actor.require(AccessFilter.Role.ADMIN);
        var value=change.asset();
        if (!id.equals(value.assetId())) throw ApiError.invalid("ASSET_ID_MISMATCH");
        var members=new TreeSet<>(value.members());
        String canonical=dispatch.encode(List.of(value.assetId(),value.appId(),value.environmentName(),value.zoneId(),
                value.agentId(),value.displayName(),members,change.active()));
        String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        var existing=store.find(Records.Asset.class,"SELECT * FROM asset_instance WHERE asset_id=? FOR UPDATE",id);
        if (existing.isEmpty()) registry.registerAsset(actor,value);
        Status status=get(actor,id);
        if (change.sourceRevision()<status.sourceRevision()) throw ApiError.conflict("STALE_SOURCE_REVISION");
        if (change.sourceRevision()==status.sourceRevision()) {
            if (!digest.equals(status.sourceDigest())) throw ApiError.conflict("SOURCE_EVENT_CHANGED");
            return status;
        }
        boolean moved=existing.isPresent() && (!existing.get().agentId().equals(value.agentId()) ||
                !existing.get().zoneId().equals(value.zoneId()) || !existing.get().appId().equals(value.appId()) ||
                !existing.get().environmentName().equals(value.environmentName()));
        for (String target:store.values(String.class,"SELECT target_id FROM jvm_target WHERE asset_id=? ORDER BY target_id",id)) {
            var control=dispatch.lock(target);
            if (moved && (!Set.of("RELEASED","TARGET_GONE").contains(control.attachState()) || control.activeTaskId()!=null))
                throw ApiError.conflict("DRAIN_BEFORE_MOVE");
            boolean retire=moved || !change.active();
            if (retire) store.write("UPDATE jvm_target SET retired=TRUE WHERE target_id=?",target);
            for (var grant:store.list(Records.Grant.class,"SELECT * FROM diagnosis_grant WHERE target_id=? AND state IN ('GRANTED','PENDING')",target)) {
                if (retire || !members.contains(grant.requesterId())) {
                    store.write("UPDATE diagnosis_grant SET state='REVOKED', revision=revision+1 WHERE grant_id=?",grant.grantId());
                    dispatch.revoke(control,grant.grantId());
                    store.audit(actor.id(),"GRANT_REVOKED",target,grant.grantId(),null,"INVENTORY_CHANGE");
                }
            }
        }
        registry.ensureZone(value.zoneId());
        store.write("""
                UPDATE asset_instance SET app_id=?,environment_name=?,zone_id=?,agent_id=?,display_name=?,
                inventory_active=?,source_revision=?,source_digest=? WHERE asset_id=?
                """,value.appId(),value.environmentName(),value.zoneId(),value.agentId(),value.displayName(),
                change.active(),change.sourceRevision(),digest,id);
        store.write("DELETE FROM asset_member WHERE asset_id=?",id);
        for (String member:members) store.write("INSERT INTO asset_member VALUES (?,?)",id,member);
        store.audit(actor.id(),"INVENTORY_SYNC",null,null,null,id);
        return get(actor,id);
    }
}
