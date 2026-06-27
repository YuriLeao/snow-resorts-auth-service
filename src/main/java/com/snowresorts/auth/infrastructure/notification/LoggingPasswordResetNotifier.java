package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fallback {@link PasswordResetNotifier} that logs the reset token instead of sending an email.
 * Activated when {@code spring.mail.host} is not configured (see {@link PasswordResetNotifierConfig}).
 */
public class LoggingPasswordResetNotifier implements PasswordResetNotifier {

    private static final Logger log = LoggerFactory.getLogger(LoggingPasswordResetNotifier.class);

    @Override
    public void sendPasswordReset(String email, String rawToken) {
        log.info("Password reset requested for {} — deliver this single-use token to the user: {}",
                email, rawToken);
    }
}
