package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.StringUtils;

@Configuration
public class PasswordResetNotifierConfig {

    /**
     * Picks SMTP delivery when {@code spring.mail.host} is set and {@link JavaMailSender} is available;
     * otherwise falls back to logging the raw token (local dev without Mailpit).
     */
    @Bean
    PasswordResetNotifier passwordResetNotifier(ObjectProvider<JavaMailSender> mailSender,
                                                AuthTokenProperties properties,
                                                Environment environment,
                                                @Value("${spring.mail.username:noreply@snow-resorts.local}") String from) {
        String host = environment.getProperty("spring.mail.host");
        if (StringUtils.hasText(host)) {
            JavaMailSender sender = mailSender.getIfAvailable();
            if (sender != null) {
                return new SmtpPasswordResetNotifier(sender, properties, from);
            }
        }
        return new LoggingPasswordResetNotifier();
    }
}
