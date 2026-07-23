package com.snowresorts.auth.application;

import com.snowresorts.auth.domain.model.PasswordResetToken;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import com.snowresorts.auth.domain.port.PasswordResetTokens;
import com.snowresorts.auth.domain.port.RefreshTokens;
import com.snowresorts.auth.domain.port.UserAccounts;
import com.snowresorts.security.error.BadRequestException;
import com.snowresorts.security.jwt.AccessTokenRevocationStore;
import com.snowresorts.security.logging.StructuredLogger;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Password-recovery use cases. Reset tokens are opaque, single-use and time-limited; only their
 * SHA-256 hash is persisted (mirroring {@link RefreshTokenCodec}). To avoid account enumeration,
 * {@link #requestReset} behaves identically whether or not the email maps to an account.
 */
@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    private final UserAccounts userAccounts;
    private final PasswordResetTokens passwordResetTokens;
    private final PasswordResetNotifier notifier;
    private final RefreshTokens refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenRevocationStore accessTokenRevocationStore;
    private final Duration passwordResetTtl;
    private final Duration accessTokenTtl;

    public PasswordResetService(UserAccounts userAccounts,
                                PasswordResetTokens passwordResetTokens,
                                PasswordResetNotifier notifier,
                                RefreshTokens refreshTokens,
                                PasswordEncoder passwordEncoder,
                                AccessTokenRevocationStore accessTokenRevocationStore,
                                AuthTokenProperties properties) {
        this.userAccounts = userAccounts;
        this.passwordResetTokens = passwordResetTokens;
        this.notifier = notifier;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenRevocationStore = accessTokenRevocationStore;
        this.passwordResetTtl = properties.passwordResetTtl();
        this.accessTokenTtl = properties.accessTokenTtl();
    }

    /**
     * Issues a password-reset token for the account behind {@code email}, if one exists, and
     * dispatches it via the {@link PasswordResetNotifier}. Always returns normally — callers must
     * not be able to tell whether the account exists.
     */
    @Transactional
    public void requestReset(String email) {
        userAccounts.findByEmail(normalize(email)).ifPresentOrElse(account -> {
            String rawToken = RefreshTokenCodec.newRawToken();
            passwordResetTokens.save(account.id(), RefreshTokenCodec.hash(rawToken),
                    Instant.now().plus(passwordResetTtl));
            notifier.sendPasswordReset(account.email(), rawToken);
            StructuredLogger.of(log).info("password_reset_request", "succeeded", "issued",
                    "user_id", account.id());
        }, () -> StructuredLogger.of(log).info("password_reset_request", "accepted", "unknown_email"));
    }

    /**
     * Consumes a reset token: validates it, sets the new (hashed) password, marks the token used
     * and revokes every active session so existing tokens cannot survive a credential reset.
     *
     * @throws BadRequestException if the token is unknown, already used or expired
     */
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken token = passwordResetTokens.findByTokenHash(RefreshTokenCodec.hash(rawToken))
                .filter(t -> t.isUsable(Instant.now()))
                .orElseThrow(() -> new BadRequestException("Invalid or expired password reset token."));

        Instant now = Instant.now();
        userAccounts.updatePassword(token.userId(), passwordEncoder.encode(newPassword));
        passwordResetTokens.markUsed(token.id());
        refreshTokens.revokeAllForUser(token.userId());
        accessTokenRevocationStore.revokeAllIssuedAtOrBefore(token.userId(), now, accessTokenTtl);
        StructuredLogger.of(log).info("password_reset", "succeeded", "sessions_revoked",
                "user_id", token.userId());
    }

    private String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
