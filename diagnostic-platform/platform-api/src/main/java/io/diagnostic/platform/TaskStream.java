package io.diagnostic.platform;

import jakarta.annotation.PreDestroy;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

@RestController
class TaskStream {
    private static final Set<String> TERMINAL = Set.of("SUCCEEDED","FAILED","CANCELLED","TIMED_OUT");
    private final Dispatch dispatch;
    private final ThreadPoolExecutor pool = new ThreadPoolExecutor(0, 16, 30, TimeUnit.SECONDS,
            new SynchronousQueue<>(), runnable -> {
                Thread thread = new Thread(runnable, "task-event-stream");
                thread.setDaemon(true);
                return thread;
            });

    TaskStream(Dispatch dispatch) { this.dispatch = dispatch; }

    @GetMapping(value="/api/v1/tasks/{id}/events", produces=MediaType.TEXT_EVENT_STREAM_VALUE)
    SseEmitter subscribe(@RequestAttribute(AccessFilter.ACTOR) AccessFilter.Actor actor, @PathVariable String id,
                         @RequestHeader(value="Last-Event-ID", defaultValue="0") long cursor) {
        if (cursor < 0) throw ApiError.invalid("INVALID_CURSOR");
        dispatch.lookupTask(actor,id);
        SseEmitter emitter = new SseEmitter(22000L);
        AtomicBoolean closed = new AtomicBoolean();
        emitter.onCompletion(() -> closed.set(true));
        emitter.onTimeout(() -> closed.set(true));
        try {
            pool.execute(() -> stream(actor,id,cursor,emitter,closed));
        } catch (RejectedExecutionException busy) {
            throw new ApiError(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS,"STREAM_LIMIT");
        }
        return emitter;
    }

    private void stream(AccessFilter.Actor actor,String id,long cursor,SseEmitter emitter,AtomicBoolean closed) {
        try {
            long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(18);
            while (!closed.get() && System.nanoTime() < end) {
                List<Dispatch.TaskEvent> events = dispatch.events(actor,id,cursor);
                for (var event : events) {
                    emitter.send(SseEmitter.event().id(Long.toString(event.sequenceNo())).name("state").data(event));
                    cursor = event.sequenceNo();
                    if (TERMINAL.contains(event.state())) return;
                }
                Thread.sleep(400);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (ApiError denied) {
            // Authorization is checked again on each batch; stop immediately on revocation.
        } catch (java.io.IOException | IllegalStateException disconnected) {
            // A reconnect resumes from Last-Event-ID.
        } finally {
            emitter.complete();
        }
    }

    @PreDestroy void stop() { pool.shutdownNow(); }
}
