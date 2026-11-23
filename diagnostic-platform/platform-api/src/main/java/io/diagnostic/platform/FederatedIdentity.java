package io.diagnostic.platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

@Component
final class FederatedIdentity {
    private final NimbusJwtDecoder decoder;
    private final String audience;
    private final Map<String,AccessFilter.Role> roles=new HashMap<>();

    FederatedIdentity(@Value("${DIAGNOSTIC_SSO_PUBLIC_KEY:}") String keyFile,
                      @Value("${DIAGNOSTIC_SSO_ISSUER:}") String issuer,
                      @Value("${DIAGNOSTIC_SSO_AUDIENCE:}") String audience,
                      @Value("${DIAGNOSTIC_SSO_SUBJECTS:}") String bindings) throws Exception {
        this.audience=audience;
        if (keyFile.isBlank() && issuer.isBlank() && audience.isBlank() && bindings.isBlank()) {
            decoder=null;
            return;
        }
        if (issuer.isBlank() || audience.isBlank() || bindings.isBlank()) throw new IllegalArgumentException("Incomplete SSO configuration");
        String pem=Files.readString(Path.of(keyFile)).replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","").replaceAll("\\s","");
        var key=(RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
        if (key.getModulus().bitLength()<2048) throw new IllegalArgumentException("Unsupported SSO key size");
        decoder=NimbusJwtDecoder.withPublicKey(key).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        for (String pair:bindings.split(",",-1)) {
            String[] binding=pair.split("=",2);
            if (binding.length!=2 || !binding[0].matches("[a-z0-9][a-z0-9._-]{0,94}")) throw new IllegalArgumentException("Invalid SSO subject");
            var role=AccessFilter.Role.valueOf(binding[1]);
            if (role==AccessFilter.Role.EXECUTOR || roles.put(binding[0],role)!=null) throw new IllegalArgumentException("Invalid SSO role binding");
        }
    }

    AccessFilter.Actor resolve(String token) {
        if (decoder==null) return null;
        try {
            Jwt jwt=decoder.decode(token);
            if (jwt.getExpiresAt()==null || jwt.getExpiresAt().toEpochMilli()<=System.currentTimeMillis()
                    || jwt.getAudience()==null || !jwt.getAudience().contains(audience)) return null;
            var role=roles.get(jwt.getSubject());
            return role==null ? null : new AccessFilter.Actor("sso."+jwt.getSubject(),role,jwt.getExpiresAt().toEpochMilli());
        } catch (JwtException | IllegalArgumentException invalid) {
            return null;
        }
    }
}
