package com.snowresorts.auth.domain.port;

import com.snowresorts.auth.domain.model.PasswordResetToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Outbound port for single-use password-reset token persistence. Only token hashes are stored. */
public interface PasswordResetTokens {

    PasswordResetToken save(UUID userId, String tokenHash, Instant expiresAt);

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    void markUsed(UUID tokenId);
}
