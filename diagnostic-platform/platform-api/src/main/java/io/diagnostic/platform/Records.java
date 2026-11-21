package io.diagnostic.platform;

import io.diagnostic.protocol.Capability;
import io.diagnostic.protocol.TaskState;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import java.util.List;
import java.util.Set;

final class Records {
    static final String KEY = "[a-z0-9][a-z0-9._-]{0,99}";

    record Asset(String assetId, String appId, String environmentName, String zoneId,
                 String agentId, String displayName) {}

    record AssetInput(@Pattern(regexp = KEY) @NotNull String assetId,
                      @Pattern(regexp = KEY) @NotNull String appId,
                      @Pattern(regexp = "[a-z][a-z0-9-]{0,31}") @NotNull String environmentName,
                      @Pattern(regexp = KEY) @NotNull String zoneId,
                      @Pattern(regexp = KEY) @NotNull String agentId,
                      @NotBlank @Size(max = 160) String displayName,
                      @NotEmpty @Size(max = 20) List<@NotNull @Pattern(regexp = KEY) String> members) {}

    record Target(String targetId, String assetId, String fingerprint, int javaFeature) {}

    record Candidate(String targetId, int javaFeature) {}

    record TargetInput(@Pattern(regexp = KEY) @NotNull String targetId,
                       @NotNull @Pattern(regexp = "[a-z0-9][a-z0-9:._-]{0,189}") String fingerprint,
                       @Min(8) int javaFeature) {}

    record Grant(String grantId, String targetId, String requesterId, String capabilities,
                 String ticketId, String state, long expiresAt, long revision) {}

    record GrantInput(@NotNull @Pattern(regexp = KEY) String targetId,
                      @NotEmpty Set<@NotNull Capability> capabilities,
                      @NotBlank @Size(max = 100) String ticketId,
                      @Positive long requestedUntil) {}

    enum Decision { APPROVE, DENY, REVOKE }

    record DecisionInput(@NotBlank @Size(max = 100) String eventId, @NotNull Decision decision,
                         @NotNull @Pattern(regexp = KEY) String reasonCode,
                         @Positive long expectedRevision) {}

    record DecisionRecord(String grantId, String actorId, String decision, String reasonCode,
                          long resultingRevision) {}

    record OpenInput(@NotNull @Pattern(regexp = KEY) String targetId, @NotBlank String grantId) {}

    record Session(String sessionId, String targetId, String grantId, String actorId,
                   long generation, long expiresAt, String state) {}

    record TaskInput(@NotNull Capability capability) {}

    record Task(String taskId, String sessionId, String targetId, String actorId, long generation,
                Capability capability, TaskState state, long deadlineAt, String cancelReason,
                String resultJson) {}

    record TaskView(String taskId, String targetId, Capability capability, TaskState state,
                    long generation, long deadlineAt, Snapshot result) {}

    record Control(String targetId, long generation, String attachState, String activeTaskId) {}

    enum OperationType { ATTACH, SNAPSHOT, CANCEL, RELEASE }
    enum Completion { ATTACHED, DONE, STOPPED, RELEASED, FAILED, UNKNOWN, TARGET_GONE }

    record Operation(String operationId, String targetId, String agentId, long generation,
                     OperationType operationType, String taskId, long availableAt,
                     Long leaseUntil, String leaseToken, String state) {}

    record Delivery(String operationId, String leaseToken, String targetId, String fingerprint,
                    long generation, OperationType type, String taskId, long leaseUntil, Long taskDeadline) {}

    record Snapshot(@NotNull @PositiveOrZero Long heapUsedBytes, @NotNull @PositiveOrZero Long heapCommittedBytes,
                    @NotNull @PositiveOrZero Long nonHeapUsedBytes, @NotNull @PositiveOrZero Long uptimeMillis,
                    @NotNull @PositiveOrZero Integer threadCount) {}
    record CompletionInput(@NotBlank String leaseToken, @NotNull Completion completion,
                           @Valid Snapshot result) {}

    record Audit(String eventId, String actorId, String action, String targetId, String grantId,
                 String taskId, String reasonCode, long occurredAt) {}

    private Records() {}
}
