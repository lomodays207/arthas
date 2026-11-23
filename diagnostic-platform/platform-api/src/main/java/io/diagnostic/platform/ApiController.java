package io.diagnostic.platform;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static io.diagnostic.platform.AccessFilter.ACTOR;
import static io.diagnostic.platform.Records.*;

@RestController
@RequestMapping("/api/v1")
class ApiController {
    private final Registry registry;
    private final Dispatch dispatch;
    private final Deliveries deliveries;

    ApiController(Registry registry, Dispatch dispatch, Deliveries deliveries) {
        this.registry = registry;
        this.dispatch = dispatch;
        this.deliveries = deliveries;
    }

    @GetMapping("/me")
    AccessFilter.Actor identity(@RequestAttribute(ACTOR) AccessFilter.Actor actor) {
        return actor;
    }

    @GetMapping("/grants")
    List<Grant> grants(@RequestAttribute(ACTOR) AccessFilter.Actor actor) {
        return registry.grants(actor);
    }

    @PostMapping("/assets")
    ResponseEntity<Asset> registerAsset(@RequestAttribute(ACTOR) AccessFilter.Actor actor,
                                        @Valid @RequestBody AssetInput input) {
        return ResponseEntity.status(201).body(registry.registerAsset(actor, input));
    }

    @GetMapping("/assets")
    List<Asset> assets(@RequestAttribute(ACTOR) AccessFilter.Actor actor) {
        return registry.assets(actor);
    }

    @PostMapping("/assets/{id}/jvms")
    ResponseEntity<Candidate> registerTarget(@RequestAttribute(ACTOR) AccessFilter.Actor actor,
                                              @PathVariable String id, @Valid @RequestBody TargetInput input) {
        return ResponseEntity.status(201).body(registry.registerTarget(actor, id, input));
    }

    @GetMapping("/assets/{id}/jvms")
    List<Candidate> candidates(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return registry.candidates(actor, id);
    }

    @PostMapping("/grants")
    ResponseEntity<Grant> requestGrant(@RequestAttribute(ACTOR) AccessFilter.Actor actor,
                                       @Valid @RequestBody GrantInput input) {
        return ResponseEntity.status(201).body(registry.requestGrant(actor, input));
    }

    @GetMapping("/grants/{id}")
    Grant grant(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return registry.getGrant(actor, id);
    }

    @PostMapping("/grants/{id}/decisions")
    Grant decide(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id,
                  @Valid @RequestBody DecisionInput input) {
        return registry.decide(actor, id, input);
    }

    @PostMapping("/sessions")
    ResponseEntity<Session> open(@RequestAttribute(ACTOR) AccessFilter.Actor actor,
                                  @Valid @RequestBody OpenInput input) {
        return ResponseEntity.accepted().body(dispatch.open(actor, input));
    }

    @GetMapping("/sessions/{id}")
    Session session(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return dispatch.lookupSession(actor, id);
    }

    @PostMapping("/sessions/{id}/heartbeat")
    Session heartbeat(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return dispatch.heartbeat(actor, id);
    }

    @DeleteMapping("/sessions/{id}")
    Session close(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return dispatch.close(actor, id);
    }

    @GetMapping("/sessions/{id}/overview")
    Dispatch.Overview overview(@RequestAttribute(ACTOR) AccessFilter.Actor actor,@PathVariable String id) {
        return dispatch.overview(actor,id,false);
    }

    @PostMapping("/sessions/{id}/overview")
    Dispatch.Overview sampleOverview(@RequestAttribute(ACTOR) AccessFilter.Actor actor,@PathVariable String id) {
        return dispatch.overview(actor,id,true);
    }

    @PostMapping("/sessions/{id}/tasks")
    ResponseEntity<TaskView> submit(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id,
                                    @RequestHeader(value = "Idempotency-Key", required = false) String key,
                                    @Valid @RequestBody TaskInput input) {
        return ResponseEntity.accepted().body(dispatch.submit(actor, id, key, input));
    }

    @GetMapping("/tasks/{id}")
    TaskView task(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return dispatch.lookupTask(actor, id);
    }

    @PostMapping("/tasks/{id}/cancel")
    ResponseEntity<TaskView> cancel(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id) {
        return ResponseEntity.accepted().body(dispatch.cancel(actor, id));
    }

    record Drain(@jakarta.validation.constraints.Positive long generation,
                 @jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max=100) String ticketId) {}
    record Lease(@jakarta.validation.constraints.NotBlank String leaseToken) {}

    @PostMapping("/targets/{id}/drain")
    ResponseEntity<Void> drain(@RequestAttribute(ACTOR) AccessFilter.Actor actor,@PathVariable String id,@Valid @RequestBody Drain body) {
        dispatch.emergency(actor,id,body.generation(),body.ticketId());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/edge/operations/{id}/authority")
    Deliveries.Authority authority(@RequestAttribute(ACTOR) AccessFilter.Actor actor,@PathVariable String id,@Valid @RequestBody Lease lease) {
        return deliveries.authority(actor,id,lease.leaseToken());
    }

    @PostMapping("/edge/claims")
    ResponseEntity<Delivery> claim(@RequestAttribute(ACTOR) AccessFilter.Actor actor) {
        Delivery delivery = deliveries.claim(actor);
        return delivery == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(delivery);
    }

    @PostMapping("/edge/operations/{id}/complete")
    ResponseEntity<Void> complete(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @PathVariable String id,
                                   @Valid @RequestBody CompletionInput input) {
        deliveries.complete(actor, id, input);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/edge/targets/{id}/generations/{generation}/released")
    ResponseEntity<Void> released(@RequestAttribute(ACTOR) AccessFilter.Actor actor,
                                  @PathVariable String id, @PathVariable long generation) {
        deliveries.reportRelease(actor, id, generation);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/audit/events")
    List<Audit> audit(@RequestAttribute(ACTOR) AccessFilter.Actor actor, @RequestParam String targetId) {
        return registry.audit(actor, targetId);
    }
}
