package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Sends password-reset instructions via SMTP when {@code spring.mail.host} is configured.
 */
public class SmtpPasswordResetNotifier implements PasswordResetNotifier {

    private static final Logger log = LoggerFactory.getLogger(SmtpPasswordResetNotifier.class);

    private final JavaMailSender mailSender;
    private final AuthTokenProperties properties;
    private final String fromAddress;

    public SmtpPasswordResetNotifier(JavaMailSender mailSender,
                                     AuthTokenProperties properties,
                                     String fromAddress) {
        this.mailSender = mailSender;
        this.properties = properties;
        this.fromAddress = fromAddress;
    }

    @Override
    public void sendPasswordReset(String email, String rawToken) {
        String resetLink = buildResetLink(rawToken);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(email);
        message.setSubject("Reset your Snow Resorts password");
        message.setText("""
                Hello,

                We received a request to reset the password for your Snow Resorts account.

                Open the link below to choose a new password (valid for a limited time):

                %s

                If you did not request this, you can ignore this email.

                — Snow Resorts
                """.formatted(resetLink));
        try {
            mailSender.send(message);
            log.info("Password reset email sent to {}", email);
        } catch (MailException ex) {
            log.error("Failed to send password reset email to {} — token was issued but not delivered",
                    email, ex);
        }
    }

    String buildResetLink(String rawToken) {
        String baseUrl = properties.passwordResetBaseUrl().strip();
        if (baseUrl.contains("?")) {
            return baseUrl + "&token=" + rawToken;
        }
        return baseUrl + "?token=" + rawToken;
    }
}
