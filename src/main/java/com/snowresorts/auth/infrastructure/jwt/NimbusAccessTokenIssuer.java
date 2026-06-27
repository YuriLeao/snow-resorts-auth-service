package com.snowresorts.auth.infrastructure.jwt;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.model.IssuedAccessToken;
import com.snowresorts.auth.domain.model.UserAccount;
import com.snowresorts.auth.domain.port.AccessTokenIssuer;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

/** Signs RS256 access tokens with the subject set to the account id and a {@code roles} claim. */
@Component
public class NimbusAccessTokenIssuer implements AccessTokenIssuer {

    private final JwtEncoder jwtEncoder;
    private final RsaKeyProvider keyProvider;
    private final AuthTokenProperties properties;

    public NimbusAccessTokenIssuer(JwtEncoder jwtEncoder, RsaKeyProvider keyProvider,
                                   AuthTokenProperties properties) {
        this.jwtEncoder = jwtEncoder;
        this.keyProvider = keyProvider;
        this.properties = properties;
    }

    @Override
    public IssuedAccessToken issue(UserAccount account) {
        Instant now = Instant.now();
        long ttlSeconds = properties.accessTokenTtl().toSeconds();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(ttlSeconds))
                .subject(account.id().toString())
                .id(UUID.randomUUID().toString())
                .claim("email", account.email())
                .claim("roles", List.of("USER"))
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keyProvider.signingKey().getKeyID())
                .build();

        String value = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new IssuedAccessToken(value, ttlSeconds);
    }
}
