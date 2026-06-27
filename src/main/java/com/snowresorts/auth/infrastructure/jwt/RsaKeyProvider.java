package com.snowresorts.auth.infrastructure.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.snowresorts.auth.application.AuthTokenProperties;
import org.springframework.stereotype.Component;

/**
 * Supplies the RSA signing key for access tokens and exposes its public half for the JWKS
 * endpoint. For local/dev an ephemeral 2048-bit key is generated at startup; downstream
 * services fetch the public key dynamically from JWKS, so rotation across restarts is fine.
 * In AWS the private key is injected from Secrets Manager (out of scope here).
 */
@Component
public class RsaKeyProvider {

    private final RSAKey rsaKey;

    public RsaKeyProvider(AuthTokenProperties properties) {
        try {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .keyID(properties.keyId())
                    .generate();
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
}
