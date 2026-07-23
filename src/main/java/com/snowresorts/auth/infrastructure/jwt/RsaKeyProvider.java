package com.snowresorts.auth.infrastructure.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.security.logging.StructuredLogger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/**
 * Supplies the RSA signing key for access tokens and exposes its public half for the JWKS
 * endpoint. When {@code snow.auth.signing-key-pem} / {@code JWT_SECRET} contains a PKCS#8 PEM,
 * that key is used. Otherwise an ephemeral key is generated only under the {@code local} or
 * {@code test} profiles; every other profile fails fast.
 */
@Component
public class RsaKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyProvider.class);

    private final RSAKey rsaKey;

    public RsaKeyProvider(AuthTokenProperties properties, Environment environment) {
        String pem = properties.signingKeyPem();
        if (pem != null && looksLikePem(pem)) {
            this.rsaKey = loadFromPem(pem, properties.keyId());
            StructuredLogger.of(log).info("rsa_key_load", "succeeded", "pem",
                    "kid", properties.keyId());
            return;
        }
        boolean allowEphemeral = environment.acceptsProfiles(Profiles.of("local", "test"));
        if (!allowEphemeral) {
            throw new IllegalStateException(
                    "snow.auth.signing-key-pem / JWT_SECRET must contain an RSA PKCS#8 PEM private key "
                            + "outside local/test profiles");
        }
        try {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .keyID(properties.keyId())
                    .generate();
            StructuredLogger.of(log).warn("rsa_key_load", "accepted", "ephemeral",
                    "kid", properties.keyId());
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to generate RSA signing key", e);
        }
    }

    /** Full key (public + private) used for signing. */
    public RSAKey signingKey() {
        return rsaKey;
    }

    /** Public-only key published via JWKS for token validation by other services. */
    public RSAKey publicKey() {
        return rsaKey.toPublicJWK();
    }

    private static boolean looksLikePem(String value) {
        String trimmed = value.trim();
        return trimmed.contains("BEGIN") && trimmed.contains("PRIVATE KEY");
    }

    private static RSAKey loadFromPem(String pem, String keyId) {
        try {
            String normalized = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(normalized);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
            if (!(privateKey instanceof RSAPrivateCrtKey crt)) {
                throw new IllegalStateException("JWT signing key must be an RSA CRT private key");
            }
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                    new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load RSA signing key from PEM", ex);
        }
    }
}
