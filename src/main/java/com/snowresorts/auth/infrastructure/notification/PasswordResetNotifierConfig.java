package com.snowresorts.auth.infrastructure.notification;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class PasswordResetNotifierConfig {

    @Bean
    @ConditionalOnProperty(name = "spring.mail.host")
    @ConditionalOnBean(JavaMailSender.class)
    PasswordResetNotifier smtpPasswordResetNotifier(JavaMailSender mailSender,
                                                      AuthTokenProperties properties,
                                                      @Value("${spring.mail.username:noreply@snow-resorts.local}") String from) {
        return new SmtpPasswordResetNotifier(mailSender, properties, from);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordResetNotifier.class)
    PasswordResetNotifier loggingPasswordResetNotifier() {
        return new LoggingPasswordResetNotifier();
    }
}
