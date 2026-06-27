package com.snowresorts.auth.infrastructure.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.model.IssuedAccessToken;
import com.snowresorts.auth.domain.model.UserAccount;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

class JwtTokenIssuanceTest {

    private static final UUID USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private RsaKeyProvider keyProvider;
    private NimbusAccessTokenIssuer issuer;
    private AuthTokenProperties properties;

    @BeforeEach
    void setUp() {
        properties = new AuthTokenProperties("https://auth.test",
                Duration.ofMinutes(15), Duration.ofDays(30), "test-key", Duration.ofHours(1),
                null, null, null);
        keyProvider = new RsaKeyProvider(properties);
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(keyProvider.signingKey()));
        issuer = new NimbusAccessTokenIssuer(new NimbusJwtEncoder(jwkSource), keyProvider, properties);
    }

    @Test
    @DisplayName("issued access token is verifiable with the published JWKS public key and carries expected claims")
    @SuppressWarnings("unchecked")
    void issue_thenValidateWithPublicKey_succeedsWithClaims() throws Exception {
        // Arrange
        UserAccount account = new UserAccount(USER_ID, "demo@snow-resorts.com", "hash", true);

        // Act
        IssuedAccessToken token = issuer.issue(account);

        RSAPublicKey publicKey = keyProvider.publicKey().toRSAPublicKey();
        JwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        Jwt decoded = decoder.decode(token.value());

        // Assert
        assertThat(token.expiresInSeconds()).isEqualTo(900);
        assertThat(decoded.getSubject()).isEqualTo(USER_ID.toString());
        assertThat(decoded.getIssuer()).hasToString("https://auth.test");
        assertThat(decoded.<String>getClaim("email")).isEqualTo("demo@snow-resorts.com");
        assertThat((List<String>) decoded.getClaim("roles")).contains("USER");
        assertThat(decoded.getExpiresAt()).isNotNull();
    }

    @Test
    @DisplayName("published JWKS exposes only public key material (no private exponent)")
    void publicKey_doesNotExposePrivateMaterial() {
        assertThat(keyProvider.publicKey().isPrivate()).isFalse();
        assertThat(keyProvider.publicKey().getKeyID()).isEqualTo("test-key");
    }
}
