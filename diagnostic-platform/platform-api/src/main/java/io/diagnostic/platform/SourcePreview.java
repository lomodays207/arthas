package io.diagnostic.platform;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import io.diagnostic.protocol.Capability;

@RestController
class SourcePreview {
    private record Entry(String text,long expires) {}
    private final Map<String,Entry> entries=new LinkedHashMap<>();
    private final Set<String> apps;
    private final Store store;
    SourcePreview(Store store,@Value("${DIAGNOSTIC_CODE_VIEW_APPS:}") String apps) {
        this.store=store;
        this.apps=Arrays.stream(apps.split(",")).filter(s->!s.isBlank()).collect(Collectors.toUnmodifiableSet());
    }

    void requireEnabled(String target) {
        String app=store.values(String.class,"SELECT a.app_id FROM asset_instance a JOIN jvm_target t ON t.asset_id=a.asset_id WHERE t.target_id=?",target).get(0);
        if (!apps.contains(app)) throw ApiError.forbidden();
    }

    void publish(String task,String text) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override public void afterCommit() { remember(task,text); }
        });
    }

    private synchronized void remember(String task,String text) {
        purge();
        if (entries.size()>=128) entries.remove(entries.keySet().iterator().next());
        entries.put(task,new Entry(text,store.now()+60000));
    }
    @Scheduled(fixedDelay=15000)
    synchronized void purge() { entries.values().removeIf(e->e.expires()<=store.now()); }

    @GetMapping("/api/v1/tasks/{id}/source") @Transactional
    public ResponseEntity<Map<String,String>> read(@RequestAttribute(AccessFilter.ACTOR) AccessFilter.Actor actor,@PathVariable String id) {
        actor.require(AccessFilter.Role.OPERATOR);
        var task=store.get(Records.Task.class,"SELECT * FROM diagnosis_task WHERE task_id=?",id);
        if (!actor.id().equals(task.actorId()) || task.capability()!=Capability.CODE_VIEW) throw ApiError.forbidden();
        requireEnabled(task.targetId());
        if (store.count("""
                SELECT COUNT(*) FROM diagnosis_session s JOIN diagnosis_grant g ON s.grant_id=g.grant_id
                WHERE s.session_id=? AND g.state='GRANTED' AND g.expires_at>?
                """,task.sessionId(),store.now())!=1) throw ApiError.forbidden();
        Entry entry;
        synchronized(this) { purge(); entry=entries.get(id); }
        if (entry==null) throw ApiError.missing();
        store.audit(actor.id(),"SOURCE_VIEWED",task.targetId(),null,id,null);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of("source",entry.text()));
    }
}
