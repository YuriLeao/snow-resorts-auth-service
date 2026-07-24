package com.snowresorts.auth.infrastructure.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.ArrayList;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** Wires the Nimbus JWT encoder/decoder used to sign and verify access tokens. */
@Configuration(proxyBeanMethods = false)
public class JwtConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource(RsaKeyProvider keyProvider) {
        // Encoder only needs the current signing key (private material).
        return new ImmutableJWKSet<>(new JWKSet(keyProvider.signingKey()));
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Verifies Bearer access tokens (e.g. logout hints) against current + previous
     * keys so rotation does not invalidate in-flight access tokens early.
     */
    @Bean
    JwtDecoder jwtDecoder(RsaKeyProvider keyProvider) {
        List<JwtDecoder> decoders = new ArrayList<>();
        for (RSAKey key : keyProvider.verificationKeys()) {
            try {
                decoders.add(NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build());
            } catch (JOSEException ex) {
                throw new IllegalStateException("Failed to build JwtDecoder from RSA public key", ex);
            }
        }
        if (decoders.size() == 1) {
            return decoders.getFirst();
        }
        return token -> decodeWithFallback(decoders, token);
    }

    private static Jwt decodeWithFallback(List<JwtDecoder> decoders, String token) {
        JwtException last = null;
        for (JwtDecoder decoder : decoders) {
            try {
                return decoder.decode(token);
            } catch (JwtException ex) {
                last = ex;
            }
        }
        throw last != null ? last : new JwtException("Unable to decode JWT");
    }
}
