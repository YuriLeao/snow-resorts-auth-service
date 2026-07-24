package com.snowresorts.auth.domain.port;

import com.snowresorts.auth.domain.model.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Outbound port for refresh-token persistence and rotation. */
public interface RefreshTokens {

    RefreshToken save(UUID userId, String tokenHash, Instant expiresAt);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Atomically marks the token revoked only if it is still active.
     *
     * @return {@code true} if a row was updated; {@code false} if already revoked/missing (reuse)
     */
    boolean revokeIfActive(UUID tokenId);

    void revokeAllForUser(UUID userId);
}
