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

    enum Role { ADMIN, APPROVER, OPERATOR, EXECUTOR, INTEGRATION }

    record Actor(String id, Role role, @com.fasterxml.jackson.annotation.JsonIgnore long expiresAt) {
        Actor(String id, Role role) { this(id,role,Long.MAX_VALUE); }
        void require(Role expected) {
            if (role != expected || System.currentTimeMillis()>=expiresAt) {
                throw ApiError.forbidden();
            }
        }
    }

    private record Credential(byte[] secret, Actor actor) {}

    private final List<Credential> credentials = new ArrayList<>();

    private final FederatedIdentity identity;

    AccessFilter(FederatedIdentity identity,
            @Value("${diagnostic.auth.admin-token}") String admin,
            @Value("${diagnostic.auth.approver-token}") String approver,
            @Value("${diagnostic.auth.operator-token}") String operator,
            @Value("${diagnostic.auth.operator2-token:}") String operator2,
            @Value("${diagnostic.auth.executor-token}") String executor,
            @Value("${diagnostic.auth.executor-id}") String executorId,
            @Value("${DIAGNOSTIC_ITSM_TOKEN:}") String itsm,
            @Value("${DIAGNOSTIC_AGENT_TOKENS:}") String agentTokens) {
        this.identity=identity;
        register(admin, new Actor("admin", Role.ADMIN));
        register(approver, new Actor("approver", Role.APPROVER));
        register(operator, new Actor("operator", Role.OPERATOR));
        register(operator2, new Actor("operator2", Role.OPERATOR));
        register(itsm,new Actor("itsm",Role.INTEGRATION));
        register(executor, new Actor(executorId, Role.EXECUTOR));
        if (!agentTokens.isBlank()) {
            for (String entry : agentTokens.split(",", -1)) {
                String[] pair = entry.split("=", 2);
                if (pair.length != 2 || !pair[0].matches(Records.KEY) || pair[1].isEmpty()
                        || credentials.stream().anyMatch(c -> c.actor().id().equals(pair[0]))) {
                    throw new IllegalArgumentException("Invalid or duplicated agent binding");
                }
                register(pair[1], new Actor(pair[0], Role.EXECUTOR));
            }
        }
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
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return request.getMethod().equals("GET") && List.of("/actuator/health", "/console.html",
                "/console.js", "/console.css").contains(path);
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
        if (authorization!=null && authorization.startsWith("Bearer ") && authorization.length()<=8192) {
            Actor actor=identity.resolve(authorization.substring(7));
            if (actor!=null) {
                request.setAttribute(ACTOR,actor);
                chain.doFilter(request,response);
                return;
            }
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", "Bearer");
        response.setContentType("application/json");
        response.getWriter().write("{\"code\":\"AUTHENTICATION_REQUIRED\"}");
    }
}
