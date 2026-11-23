package io.diagnostic.platform;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "diagnostic.auth.admin-token=synthetic-admin-token-for-testing",
        "diagnostic.auth.approver-token=synthetic-approver-token-for-testing",
        "diagnostic.auth.operator-token=synthetic-operator-token-for-testing",
        "diagnostic.auth.operator2-token=synthetic-operator2-token-for-testing",
        "diagnostic.auth.executor-token=synthetic-executor-token-for-testing",
        "diagnostic.sweep-delay-ms=3600000"
})
@AutoConfigureMockMvc
class ControlPlaneTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate db;
    @Autowired ObjectMapper json;
    @Autowired MutableClock clock;
    @Autowired Dispatch dispatch;

    @DynamicPropertySource
    static void dataSource(DynamicPropertyRegistry props) {
        props.add("spring.datasource.url", () -> System.getenv().getOrDefault(
                "TEST_DATABASE_URL", "jdbc:h2:mem:control-plane-test;MODE=MySQL;DB_CLOSE_DELAY=-1"));
        props.add("spring.datasource.username", () -> System.getenv().getOrDefault("TEST_DATABASE_USER", "sa"));
        props.add("spring.datasource.password", () -> System.getenv().getOrDefault("TEST_DATABASE_PASSWORD", ""));
    }

    @BeforeEach
    void reset() throws Exception {
        for (String table : new String[] {"audit_event", "edge_event_inbox", "operation_outbox", "diagnosis_task",
                "diagnosis_session", "target_control", "grant_decision", "diagnosis_grant", "jvm_target",
                "asset_member", "asset_instance"}) {
            db.update("DELETE FROM " + table);
        }
        clock.set(100_000);
        write(post("/api/v1/assets"), "admin", Map.of(
                "assetId", "asset", "appId", "synthetic", "environmentName", "test", "zoneId", "zone-a",
                "agentId", "local-agent", "displayName", "Synthetic fixture", "members", new String[] {"operator", "operator2"}))
                .andExpect(status().isCreated());
        write(post("/api/v1/assets/asset/jvms"), "admin",
                Map.of("targetId", "jvm", "fingerprint", "testboot:123:456", "javaFeature", 8))
                .andExpect(status().isCreated());
    }

    @Test
    void validatesAuthorizationIdempotencyAndSnapshotEvidence() throws Exception {
        mvc.perform(get("/api/v1/assets")).andExpect(status().isUnauthorized());
        read(get("/api/v1/assets"), "operator").andExpect(jsonPath("$[0].assetId").value("asset"));
        read(get("/api/v1/assets/asset/jvms"), "operator").andExpect(jsonPath("$[0].fingerprint").doesNotExist());
        String grant = id(write(post("/api/v1/grants"), "operator", grantRequest())
                .andExpect(status().isCreated()), "grantId");
        write(post("/api/v1/sessions"), "operator", Map.of("targetId", "jvm", "grantId", grant))
                .andExpect(status().isForbidden());
        write(post("/api/v1/grants/" + grant + "/decisions"), "operator",
                decision("approve-event", "APPROVE", 1)).andExpect(status().isForbidden());
        approve(grant);
        approve(grant);
        String session = open(grant, "operator", "OPENING");
        open(grant, "operator", "OPENING");
        JsonNode attach = claim("ATTACH");
        noClaim();
        complete(attach, "ATTACHED", null);
        complete(attach, "ATTACHED", null);
        read(get("/api/v1/sessions/" + session), "operator").andExpect(jsonPath("$.state").value("ACTIVE"));
        String task = submit(session, "first");
        assertEquals(task, submit(session, "first"));
        write(post("/api/v1/sessions/" + session + "/tasks").header("Idempotency-Key", "second"),
                "operator", Map.of("capability", "JVM_OVERVIEW"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("TARGET_BUSY"));
        JsonNode snapshot = claim("SNAPSHOT");
        JsonNode invalid = snapshot.deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) invalid).put("leaseToken", "unrecognized");
        ack(invalid, "DONE", snapshotResult()).andExpect(status().isConflict());
        ack(snapshot, "DONE", Map.of("heapUsedBytes", 16)).andExpect(status().isBadRequest());
        complete(snapshot, "DONE", snapshotResult());
        complete(snapshot, "DONE", snapshotResult());
        read(get("/api/v1/tasks/" + task), "operator")
                .andExpect(jsonPath("$.state").value("SUCCEEDED"))
                .andExpect(jsonPath("$.result.heapUsedBytes").value(16));
        read(get("/api/v1/tasks/" + task), "operator2").andExpect(status().isForbidden());
        write(post("/api/v1/grants/" + grant + "/decisions"), "approver",
                decision("revoke-event", "REVOKE", 2)).andExpect(status().isOk());
        read(get("/api/v1/tasks/" + task), "operator").andExpect(status().isForbidden());
        read(get("/api/v1/audit/events").param("targetId", "jvm"), "admin")
                .andExpect(status().isOk()).andExpect(jsonPath("$[?(@.action == 'GRANT_REVOKED')]").isNotEmpty());
    }

    @Test
    void managesAdmissionAndScopedEvidence() throws Exception {
        String grant=approvedGrant("operator");
        write(put("/api/v1/assets/asset/policy"),"admin",Map.of("expectedRevision",1,"paused",true,"maxSessions",1))
                .andExpect(status().isOk());
        write(post("/api/v1/sessions"),"operator",Map.of("targetId","jvm","grantId",grant)).andExpect(status().isConflict());
        write(put("/api/v1/assets/asset/policy"),"admin",Map.of("expectedRevision",2,"paused",false,"maxSessions",1))
                .andExpect(status().isOk());
        String session=open(grant,"operator","OPENING");
        write(post("/api/v1/sessions"),"operator",Map.of("targetId","jvm","grantId",grant)).andExpect(status().isConflict());
        complete(claim("ATTACH"),"ATTACHED",null);
        String task=submit(session,"sample");
        complete(claim("SNAPSHOT"),"DONE",snapshotResult());
        String ref=id(write(post("/api/v1/tasks/"+task+"/references"),"operator",
                Map.of("readerId","operator2","expiresAt",clock.millis()+60000)).andExpect(status().isOk()),"referenceId");
        read(get("/api/v1/references/"+ref),"operator2").andExpect(status().isForbidden());
        approvedGrant("operator2");
        read(get("/api/v1/references/"+ref),"operator2").andExpect(jsonPath("$.result.threadCount").value(3));
        read(delete("/api/v1/references/"+ref),"operator").andExpect(status().isOk());
        read(get("/api/v1/references/"+ref),"operator2").andExpect(status().isForbidden());
        read(get("/api/v1/management/channels"),"admin").andExpect(jsonPath("$[0].online").value(true));
        read(get("/api/v1/management/channels"),"operator").andExpect(status().isForbidden());
    }

    @Test
    void expiredOperationStaysUncertainUntilCancellationConfirmsIt() throws Exception {
        String grant = approvedGrant("operator");
        String session = open(grant, "operator", "OPENING");
        complete(claim("ATTACH"), "ATTACHED", null);
        String task = submit(session, "expiring");
        JsonNode original = claim("SNAPSHOT");
        clock.advance(21_000);
        dispatch.sweep();
        JsonNode cancel = claim("CANCEL");
        read(get("/api/v1/tasks/" + task), "operator")
                .andExpect(jsonPath("$.state").value("RECONCILING"));
        noClaim();
        complete(cancel, "STOPPED", null);
        read(get("/api/v1/tasks/" + task), "operator")
                .andExpect(jsonPath("$.state").value("TIMED_OUT"));
        complete(original, "DONE", snapshotResult());
        read(get("/api/v1/tasks/" + task), "operator")
                .andExpect(jsonPath("$.state").value("TIMED_OUT"))
                .andExpect(jsonPath("$.result").doesNotExist());
        submit(session, "allowed-again");
    }

    @Test
    void releasesOnlyAfterLastSessionAndAdvancesGeneration() throws Exception {
        String grantOne = approvedGrant("operator");
        String grantTwo = approvedGrant("operator2");
        String first = open(grantOne, "operator", "OPENING");
        JsonNode firstAttach = claim("ATTACH");
        complete(firstAttach, "ATTACHED", null);
        String second = open(grantTwo, "operator2", "ACTIVE");
        read(delete("/api/v1/sessions/" + first), "operator").andExpect(jsonPath("$.state").value("CLOSED"));
        noClaim();
        write(post("/api/v1/sessions/" + second + "/heartbeat"), "operator2", null)
                .andExpect(status().isOk());
        read(delete("/api/v1/sessions/" + second), "operator2").andExpect(status().isOk());
        clock.advance(119_999);
        noClaim();
        String reopened = open(grantOne, "operator", "ACTIVE");
        clock.advance(1);
        noClaim();
        read(delete("/api/v1/sessions/" + reopened), "operator").andExpect(status().isOk());
        clock.advance(120_000);
        JsonNode release = claim("RELEASE");
        assertEquals(1, release.get("generation").asInt());
        complete(release, "RELEASED", null);
        open(grantOne, "operator", "OPENING");
        assertEquals(2, claim("ATTACH").get("generation").asInt());
        complete(firstAttach, "ATTACHED", null);
        noClaim();
    }

    @Test
    void concurrentExecutorClaimsDeliverAnOperationOnlyOnce() throws Exception {
        open(approvedGrant("operator"), "operator", "OPENING");
        var gate = new CyclicBarrier(2);
        var workers = Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Callable<Integer> claim = () -> {
                gate.await(5, TimeUnit.SECONDS);
                return write(post("/api/v1/edge/claims"), "executor", null)
                        .andReturn().getResponse().getStatus();
            };
            var first = workers.submit(claim);
            var second = workers.submit(claim);
            assertEquals(Set.of(200, 204), Set.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)));
        } finally {
            workers.shutdownNow();
        }
    }

    @Test
    void lostAttachCanReconcileButIsNeverAutomaticallyResent() throws Exception {
        String grant = approvedGrant("operator");
        String session = open(grant, "operator", "OPENING");
        JsonNode attach = claim("ATTACH");
        clock.advance(12_001);
        complete(attach, "UNKNOWN", null);
        noClaim();
        write(post("/api/v1/sessions"), "operator", Map.of("targetId", "jvm", "grantId", grant))
                .andExpect(status().isConflict());
        complete(attach, "ATTACHED", null);
        read(get("/api/v1/sessions/" + session), "operator").andExpect(jsonPath("$.state").value("ACTIVE"));
    }

    private ResultActions read(MockHttpServletRequestBuilder request, String actor) throws Exception {
        return mvc.perform(request.header("Authorization", "Bearer synthetic-" + actor + "-token-for-testing"));
    }

    private ResultActions write(MockHttpServletRequestBuilder request, String actor, Object payload) throws Exception {
        if (payload != null) {
            request.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(payload));
        }
        return read(request, actor);
    }

    private Map<String, ?> grantRequest() {
        return Map.of("targetId", "jvm", "capabilities", new String[] {"JVM_OVERVIEW"},
                "ticketId", "test-ticket", "requestedUntil", clock.millis() + 900_000);
    }

    private Map<String, ?> decision(String event, String decision, long revision) {
        return Map.of("eventId", event, "decision", decision, "reasonCode", "test", "expectedRevision", revision);
    }

    private void approve(String grant) throws Exception {
        write(post("/api/v1/grants/" + grant + "/decisions"), "approver",
                decision("approve-" + grant, "APPROVE", 1))
                .andExpect(status().isOk()).andExpect(jsonPath("$.state").value("GRANTED"));
    }

    private String approvedGrant(String actor) throws Exception {
        String grant = id(write(post("/api/v1/grants"), actor, grantRequest())
                .andExpect(status().isCreated()), "grantId");
        approve(grant);
        return grant;
    }

    private String open(String grant, String actor, String expected) throws Exception {
        return id(write(post("/api/v1/sessions"), actor, Map.of("targetId", "jvm", "grantId", grant))
                .andExpect(status().isAccepted()).andExpect(jsonPath("$.state").value(expected)), "sessionId");
    }

    private String submit(String session, String key) throws Exception {
        return id(write(post("/api/v1/sessions/" + session + "/tasks").header("Idempotency-Key", key),
                "operator", Map.of("capability", "JVM_OVERVIEW")).andExpect(status().isAccepted()), "taskId");
    }

    private JsonNode claim(String type) throws Exception {
        return json.readTree(write(post("/api/v1/edge/claims"), "executor", null)
                .andExpect(status().isOk()).andExpect(jsonPath("$.type").value(type))
                .andReturn().getResponse().getContentAsByteArray());
    }

    private void noClaim() throws Exception {
        write(post("/api/v1/edge/claims"), "executor", null).andExpect(status().isNoContent());
    }

    private void complete(JsonNode delivery, String outcome, Object snapshot) throws Exception {
        ack(delivery, outcome, snapshot).andExpect(status().isNoContent());
    }

    private ResultActions ack(JsonNode delivery, String outcome, Object snapshot) throws Exception {
        var fields = json.createObjectNode().put("leaseToken", delivery.get("leaseToken").asText())
                .put("completion", outcome);
        if (snapshot != null) {
            fields.set("result", json.valueToTree(snapshot));
        }
        return write(post("/api/v1/edge/operations/" + delivery.get("operationId").asText() + "/complete"),
                "executor", fields);
    }

    private Map<String, Integer> snapshotResult() {
        return Map.of("heapUsedBytes", 16, "heapCommittedBytes", 64, "nonHeapUsedBytes", 48, "uptimeMillis", 100,
                "threadCount", 3);
    }

    private String id(ResultActions response, String property) throws Exception {
        return json.readTree(response.andReturn().getResponse().getContentAsByteArray()).get(property).asText();
    }

    @TestConfiguration
    static class TestClock {
        @Bean
        @Primary
        MutableClock fixedClock() {
            return new MutableClock();
        }
    }

    static final class MutableClock extends Clock {
        private final AtomicLong millis = new AtomicLong();
        void set(long value) { millis.set(value); }
        void advance(long value) { millis.addAndGet(value); }
        @Override public long millis() { return millis.get(); }
        @Override public Instant instant() { return Instant.ofEpochMilli(millis()); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return Clock.fixed(instant(), zone); }
    }
}
