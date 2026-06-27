package com.snowresorts.auth.infrastructure.jwt;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/** Wires the Nimbus JWT encoder used to sign access tokens with the service's RSA key. */
@Configuration(proxyBeanMethods = false)
public class JwtConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource(RsaKeyProvider keyProvider) {
        return new ImmutableJWKSet<>(new JWKSet(keyProvider.signingKey()));
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}
