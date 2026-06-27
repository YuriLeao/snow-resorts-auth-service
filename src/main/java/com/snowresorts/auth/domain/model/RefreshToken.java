package com.snowresorts.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/** A persisted refresh token (only its hash is stored). Supports rotation and revocation. */
public record RefreshToken(
        UUID id,
        UUID userId,
        String tokenHash,
        Instant expiresAt,
        boolean revoked,
        Instant createdAt) {

    public boolean isActive(Instant now) {
        return !revoked && expiresAt.isAfter(now);
    }
}
