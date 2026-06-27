package com.snowresorts.auth.domain.port;

import com.snowresorts.auth.domain.model.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Outbound port for refresh-token persistence and rotation. */
public interface RefreshTokens {

    RefreshToken save(UUID userId, String tokenHash, Instant expiresAt);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    void revoke(UUID tokenId);

    void revokeAllForUser(UUID userId);
}
