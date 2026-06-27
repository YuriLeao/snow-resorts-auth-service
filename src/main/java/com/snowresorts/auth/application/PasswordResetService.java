package com.snowresorts.auth.application;

import com.snowresorts.auth.domain.model.PasswordResetToken;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import com.snowresorts.auth.domain.port.PasswordResetTokens;
import com.snowresorts.auth.domain.port.RefreshTokens;
import com.snowresorts.auth.domain.port.UserAccounts;
import com.snowresorts.security.error.BadRequestException;
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
    private final Duration passwordResetTtl;

    public PasswordResetService(UserAccounts userAccounts,
                                PasswordResetTokens passwordResetTokens,
                                PasswordResetNotifier notifier,
                                RefreshTokens refreshTokens,
                                PasswordEncoder passwordEncoder,
                                AuthTokenProperties properties) {
        this.userAccounts = userAccounts;
        this.passwordResetTokens = passwordResetTokens;
        this.notifier = notifier;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTtl = properties.passwordResetTtl();
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
            log.info("Issued password reset token for account {}", account.id());
        }, () -> log.info("Password reset requested for an unknown email; responding without action"));
    }

    /**
     * Consumes a reset token: validates it, sets the new (hashed) password, marks the token used
     * and revokes every active refresh token so existing sessions cannot survive a credential reset.
     *
     * @throws BadRequestException if the token is unknown, already used or expired
     */
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken token = passwordResetTokens.findByTokenHash(RefreshTokenCodec.hash(rawToken))
                .filter(t -> t.isUsable(Instant.now()))
                .orElseThrow(() -> new BadRequestException("Invalid or expired password reset token."));

        userAccounts.updatePassword(token.userId(), passwordEncoder.encode(newPassword));
        passwordResetTokens.markUsed(token.id());
        refreshTokens.revokeAllForUser(token.userId());
        log.info("Password reset completed for account {}; all sessions revoked", token.userId());
    }

    private String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
