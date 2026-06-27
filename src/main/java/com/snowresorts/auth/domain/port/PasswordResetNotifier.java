package com.snowresorts.auth.domain.port;

/**
 * Outbound port that delivers a password-reset token to the account owner (e.g. by email).
 * The raw token is passed only to this port and never persisted in clear text.
 */
public interface PasswordResetNotifier {

    void sendPasswordReset(String email, String rawToken);
}
