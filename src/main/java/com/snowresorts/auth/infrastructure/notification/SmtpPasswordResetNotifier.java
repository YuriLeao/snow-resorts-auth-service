package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

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
        String plainText = """
                Hello,

                We received a request to reset the password for your Snow Resorts account.

                Open the link below to choose a new password (valid for a limited time):

                %s

                If you did not request this, you can ignore this email.

                — Snow Resorts
                """.formatted(resetLink);
        String htmlText = buildHtmlBody(resetLink);
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setFrom(fromAddress);
            helper.setTo(email);
            helper.setSubject("Reset your Snow Resorts password");
            helper.addInline("appIcon", new ClassPathResource("email/app-icon.png"));
            helper.setText(plainText, htmlText);
            mailSender.send(mimeMessage);
            log.info("Password reset email sent to {}", email);
        } catch (MailException | MessagingException ex) {
            log.error("Failed to send password reset email to {} — token was issued but not delivered",
                    email, ex);
        }
    }

    static String buildHtmlBody(String resetLink) {
        return """
                <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 15px; line-height: 1.5; color: #111827;">
                  <p style="margin: 0 0 16px;">Hello,</p>
                  <p style="margin: 0 0 16px;">We received a request to reset the password for your Snow Resorts account.</p>
                  <p style="margin: 0 0 16px;">Open the link below to choose a new password (valid for a limited time):</p>
                  <p style="margin: 0 0 16px;"><a href="%s" style="color: #2563eb;">Reset your password</a></p>
                  <p style="margin: 0 0 16px;">If you did not request this, you can ignore this email.</p>
                  <p style="margin: 24px 0 8px;">&mdash; Snow Resorts</p>
                  <img src="cid:appIcon" alt="Snow Resorts" width="48" height="48" style="display: block; border-radius: 10px;" />
                </div>
                """.formatted(resetLink);
    }

    String buildResetLink(String rawToken) {
        String baseUrl = properties.passwordResetBaseUrl().strip();
        if (baseUrl.contains("?")) {
            return baseUrl + "&token=" + rawToken;
        }
        return baseUrl + "?token=" + rawToken;
    }
}
