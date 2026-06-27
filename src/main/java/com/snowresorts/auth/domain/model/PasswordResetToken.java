package com.snowresorts.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/** A single-use, time-limited password reset token (only its hash is stored). */
public record PasswordResetToken(
        UUID id,
        UUID userId,
        String tokenHash,
        Instant expiresAt,
        boolean used,
        Instant createdAt) {

    public boolean isUsable(Instant now) {
        return !used && expiresAt.isAfter(now);
    }
}
