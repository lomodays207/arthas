package io.diagnostic.platform;

import org.springframework.jdbc.core.DataClassRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
class Store {
    private final JdbcTemplate db;
    private final Clock clock;

    Store(JdbcTemplate db, Clock clock) {
        this.db = db;
        this.clock = clock;
    }

    <T> Optional<T> find(Class<T> type, String sql, Object... args) {
        return list(type, sql, args).stream().findFirst();
    }

    <T> T get(Class<T> type, String sql, Object... args) {
        return find(type, sql, args).orElseThrow(ApiError::missing);
    }

    <T> List<T> list(Class<T> type, String sql, Object... args) {
        return db.query(sql, new DataClassRowMapper<>(type), args);
    }

    <T> List<T> values(Class<T> type, String sql, Object... args) {
        return db.queryForList(sql, type, args);
    }

    int count(String sql, Object... args) {
        Integer result = db.queryForObject(sql, Integer.class, args);
        return result == null ? 0 : result;
    }

    int write(String sql, Object... args) {
        return db.update(sql, args);
    }

    long now() {
        return clock.millis();
    }

    static String id() {
        return UUID.randomUUID().toString();
    }

    void audit(String actor, String action, String target, String grant, String task, String reason) {
        write("""
                INSERT INTO audit_event (event_id, actor_id, action, target_id, grant_id,
                                         task_id, reason_code, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, id(), actor, action, target, grant, task, reason, now());
    }
}
