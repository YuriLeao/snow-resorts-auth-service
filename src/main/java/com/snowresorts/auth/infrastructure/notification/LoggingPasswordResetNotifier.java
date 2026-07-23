package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import com.snowresorts.security.logging.StructuredLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fallback {@link PasswordResetNotifier} for local/test when SMTP is not configured.
 * Logs issuance only — never the raw reset token.
 */
public class LoggingPasswordResetNotifier implements PasswordResetNotifier {

    private static final Logger log = LoggerFactory.getLogger(LoggingPasswordResetNotifier.class);

    @Override
    public void sendPasswordReset(String email, String rawToken) {
        StructuredLogger.of(log).info("password_reset_issued", "accepted", "local_log");
    }
}
