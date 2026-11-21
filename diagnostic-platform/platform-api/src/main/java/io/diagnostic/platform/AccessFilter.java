package io.diagnostic.platform;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

@Component
final class AccessFilter extends OncePerRequestFilter {
    static final String ACTOR = "io.diagnostic.platform.actor";

    enum Role { ADMIN, APPROVER, OPERATOR, EXECUTOR }

    record Actor(String id, Role role) {
        void require(Role expected) {
            if (role != expected) {
                throw ApiError.forbidden();
            }
        }
    }

    private record Credential(byte[] secret, Actor actor) {}

    private final List<Credential> credentials = new ArrayList<>();

    AccessFilter(
            @Value("${diagnostic.auth.admin-token}") String admin,
            @Value("${diagnostic.auth.approver-token}") String approver,
            @Value("${diagnostic.auth.operator-token}") String operator,
            @Value("${diagnostic.auth.operator2-token:}") String operator2,
            @Value("${diagnostic.auth.executor-token}") String executor,
            @Value("${diagnostic.auth.executor-id}") String executorId) {
        register(admin, new Actor("admin", Role.ADMIN));
        register(approver, new Actor("approver", Role.APPROVER));
        register(operator, new Actor("operator", Role.OPERATOR));
        register(operator2, new Actor("operator2", Role.OPERATOR));
        register(executor, new Actor(executorId, Role.EXECUTOR));
    }

    private void register(String token, Actor actor) {
        if (token.isEmpty()) {
            return;
        }
        if (!token.matches("[A-Za-z0-9._~-]{32,256}")) {
            throw new IllegalArgumentException("Invalid token format for " + actor.role());
        }
        byte[] secret = token.getBytes(StandardCharsets.UTF_8);
        if (credentials.stream().anyMatch(entry -> MessageDigest.isEqual(entry.secret(), secret))) {
            throw new IllegalArgumentException("Each principal requires a different token");
        }
        credentials.add(new Credential(secret, actor));
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().equals(request.getContextPath() + "/actuator/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ") && authorization.length() <= 263) {
            byte[] candidate = authorization.substring(7).getBytes(StandardCharsets.UTF_8);
            for (Credential credential : credentials) {
                if (MessageDigest.isEqual(credential.secret(), candidate)) {
                    request.setAttribute(ACTOR, credential.actor());
                    chain.doFilter(request, response);
                    return;
                }
            }
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", "Bearer");
        response.setContentType("application/json");
        response.getWriter().write("{\"code\":\"AUTHENTICATION_REQUIRED\"}");
    }
}
