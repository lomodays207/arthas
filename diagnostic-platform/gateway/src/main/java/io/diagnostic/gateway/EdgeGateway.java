package io.diagnostic.gateway;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;

@RestController
@RequestMapping("/edge/v1")
final class EdgeGateway {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private final URI upstream;
    private final Map<String,String> tokens;

    EdgeGateway(@Value("${diagnostic.platform-port:8080}") int port,
                @Value("${DIAGNOSTIC_CERT_TOKENS:}") String bindings) {
        this.upstream = URI.create("http://127.0.0.1:" + port + "/api/v1/edge/");
        var configured = new HashMap<String, String>();
        if (!bindings.isBlank()) {
            for (String entry : bindings.split(",", -1)) {
                String[] pair = entry.split("=", 2);
                if (pair.length != 2 || !pair[0].matches("[0-9a-f]{64}")
                        || !pair[1].matches("[A-Za-z0-9._~-]{32,256}")
                        || configured.containsKey(pair[0]) || configured.containsValue(pair[1])) {
                    throw new IllegalArgumentException("Invalid or duplicated certificate binding");
                }
                configured.put(pair[0], pair[1]);
            }
        }
        this.tokens = Map.copyOf(configured);
    }

    @PostMapping("/claims")
    ResponseEntity<byte[]> claim(HttpServletRequest request) throws Exception {
        return forward(request, "claims", false);
    }

    @PostMapping("/operations/{id}/authority")
    ResponseEntity<byte[]> authority(HttpServletRequest request,@PathVariable UUID id) throws Exception {
        return forward(request,"operations/"+id+"/authority",true);
    }

    @PostMapping("/operations/{id}/complete")
    ResponseEntity<byte[]> complete(HttpServletRequest request, @PathVariable UUID id) throws Exception {
        return forward(request, "operations/" + id + "/complete", true);
    }

    @PostMapping("/targets/{target}/generations/{generation}/released")
    ResponseEntity<byte[]> released(HttpServletRequest request, @PathVariable String target,
                                    @PathVariable long generation) throws Exception {
        if (!target.matches("[a-z0-9][a-z0-9._-]{0,99}") || generation < 1)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return forward(request, "targets/" + target + "/generations/" + generation + "/released", false);
    }

    private ResponseEntity<byte[]> forward(HttpServletRequest request, String path, boolean completion)
            throws Exception {
        var certificates = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!request.isSecure() || certificates == null || certificates.length == 0)
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        certificates[0].checkValidity();
        String pin = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificates[0].getEncoded()));
        String token = tokens.get(pin);
        if (token == null) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        byte[] body = request.getInputStream().readNBytes(8193);
        if (body.length > 8192 || (!completion && body.length != 0))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var outbound = HttpRequest.newBuilder(upstream.resolve(path)).timeout(Duration.ofSeconds(5))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
        try {
            var response = client.send(outbound, HttpResponse.BodyHandlers.ofByteArray());
            return ResponseEntity.status(response.statusCode()).contentType(MediaType.APPLICATION_JSON)
                    .cacheControl(CacheControl.noStore()).body(response.body());
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
        }
    }
}
