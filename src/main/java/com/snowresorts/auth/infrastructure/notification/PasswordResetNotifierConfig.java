package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.StringUtils;

@Configuration
public class PasswordResetNotifierConfig {

    /**
     * Picks SMTP delivery when {@code spring.mail.host} is set and {@link JavaMailSender} is available.
     * Outside {@code local}/{@code test}, missing SMTP host fails fast. Logging fallback is only for
     * local/test without Mailpit.
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
        boolean localOrTest = environment.acceptsProfiles(Profiles.of("local", "test"));
        if (!localOrTest) {
            throw new IllegalStateException("spring.mail.host is required outside local/test");
        }
        return new LoggingPasswordResetNotifier();
    }
}
