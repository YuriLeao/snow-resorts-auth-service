package com.snowresorts.auth.infrastructure.jwt;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/**
 * Supplies the RSA signing key for access tokens and exposes public keys for JWKS.
 *
 * <p>{@code JWT_SECRET} / {@code snow.auth.signing-key-pem} may be:
 * <ul>
 *   <li>a raw PKCS#8 PEM (legacy), or</li>
 *   <li>a JSON document {@code {currentPem,currentKid,previousPem,previousKid}} for dual-JWKS
 *       rotation without downtime.</li>
 * </ul>
 * Optionally {@code snow.auth.previous-signing-key-pem} overlays the previous verification key.
 */
@Component
public class RsaKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyProvider.class);
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final RSAKey rsaKey;
    private final RSAKey previousPublicKey;

    public RsaKeyProvider(AuthTokenProperties properties, Environment environment) {
        ParsedKeys parsed = parseKeys(properties);
        if (parsed.current() != null) {
            this.rsaKey = parsed.current();
            this.previousPublicKey = parsed.previousPublic();
            StructuredLogger.of(log).info("rsa_key_load", "succeeded", "pem",
                    "kid", this.rsaKey.getKeyID(),
                    "previous_kid", this.previousPublicKey != null ? this.previousPublicKey.getKeyID() : "");
            return;
        }
        boolean allowEphemeral = environment.acceptsProfiles(Profiles.of("local", "test"));
        if (!allowEphemeral) {
            throw new IllegalStateException(
                    "snow.auth.signing-key-pem / JWT_SECRET must contain an RSA PKCS#8 PEM private key "
                            + "(or dual-key JSON) outside local/test profiles");
        }
        try {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .keyID(properties.keyId())
                    .generate();
            this.previousPublicKey = null;
            StructuredLogger.of(log).debug("rsa_key_load", "accepted", "ephemeral",
                    "kid", properties.keyId());
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to generate RSA signing key", e);
        }
    }

    /** Full key (public + private) used for signing. */
    public RSAKey signingKey() {
        return rsaKey;
    }

    /** Public keys published via JWKS (current first, then previous when rotating). */
    public List<RSAKey> verificationKeys() {
        List<RSAKey> keys = new ArrayList<>(2);
        keys.add(rsaKey.toPublicJWK());
        if (previousPublicKey != null) {
            keys.add(previousPublicKey);
        }
        return List.copyOf(keys);
    }

    private static ParsedKeys parseKeys(AuthTokenProperties properties) {
        String raw = properties.signingKeyPem();
        String previousOverlay = properties.previousSigningKeyPem();
        String previousKid = properties.previousKeyId() != null && !properties.previousKeyId().isBlank()
                ? properties.previousKeyId()
                : properties.keyId() + "-previous";

        if (raw != null && raw.trim().startsWith("{")) {
            try {
                JsonNode node = MAPPER.readTree(raw);
                String currentPem = text(node, "currentPem");
                String currentKid = textOr(node, "currentKid", properties.keyId());
                String previousPem = text(node, "previousPem");
                String prevKid = textOr(node, "previousKid", previousKid);
                if (currentPem == null || !looksLikePem(currentPem)) {
                    throw new IllegalStateException("JWT secret JSON missing currentPem PKCS#8 PEM");
                }
                RSAKey current = loadFromPem(currentPem, currentKid);
                RSAKey previous = null;
                String overlayOrJson = previousOverlay != null && looksLikePem(previousOverlay)
                        ? previousOverlay
                        : previousPem;
                if (overlayOrJson != null && looksLikePem(overlayOrJson)) {
                    previous = loadFromPem(overlayOrJson, prevKid).toPublicJWK();
                }
                return new ParsedKeys(current, previous);
            } catch (Exception ex) {
                if (ex instanceof IllegalStateException ise) {
                    throw ise;
                }
                throw new IllegalStateException("Failed to parse JWT secret JSON", ex);
            }
        }

        if (raw != null && looksLikePem(raw)) {
            RSAKey current = loadFromPem(raw, properties.keyId());
            RSAKey previous = null;
            if (previousOverlay != null && looksLikePem(previousOverlay)) {
                previous = loadFromPem(previousOverlay, previousKid).toPublicJWK();
            }
            return new ParsedKeys(current, previous);
        }
        return new ParsedKeys(null, null);
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        String s = value.asText();
        return s == null || s.isBlank() ? null : s;
    }

    private static String textOr(JsonNode node, String field, String fallback) {
        String value = text(node, field);
        return value != null ? value : fallback;
    }

    private static boolean looksLikePem(String value) {
        String trimmed = value.trim();
        return trimmed.contains("BEGIN") && trimmed.contains("PRIVATE KEY");
    }

    private static RSAKey loadFromPem(String pem, String keyId) {
        try {
            // Split PEM armor markers so secret scanners do not treat parsers as keys.
            String begin = "-----BEGIN ";
            String end = "-----END ";
            String normalized = pem
                    .replace(begin + "PRIVATE KEY-----", "")
                    .replace(end + "PRIVATE KEY-----", "")
                    .replace(begin + "RSA PRIVATE KEY-----", "")
                    .replace(end + "RSA PRIVATE KEY-----", "")
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
            if (ex instanceof IllegalStateException ise) {
                throw ise;
            }
            throw new IllegalStateException("Failed to load RSA signing key from PEM", ex);
        }
    }

    private record ParsedKeys(RSAKey current, RSAKey previousPublic) {}
}
