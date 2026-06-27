package com.snowresorts.auth.infrastructure.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import com.snowresorts.auth.application.AuthTokenProperties;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@ExtendWith(MockitoExtension.class)
class SmtpPasswordResetNotifierTest {

    @Mock
    private JavaMailSender mailSender;

    private SmtpPasswordResetNotifier notifier;

    @BeforeEach
    void setUp() {
        AuthTokenProperties properties = new AuthTokenProperties(
                "https://auth.test",
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                "k1",
                Duration.ofHours(1),
                "http://localhost:8080/reset-password",
                "http://localhost:8082",
                "dev-internal-secret");
        notifier = new SmtpPasswordResetNotifier(mailSender, properties, "noreply@snow-resorts.local");
    }

    @Test
    @DisplayName("sendPasswordReset sends an email with a reset link containing the token")
    void sendPasswordReset_withToken_sendsEmailWithResetLink() {
        // Act
        notifier.sendPasswordReset("rider@snow-resorts.com", "opaque-token-123");

        // Assert
        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(captor.capture());
        SimpleMailMessage message = captor.getValue();
        assertThat(message.getTo()).containsExactly("rider@snow-resorts.com");
        assertThat(message.getFrom()).isEqualTo("noreply@snow-resorts.local");
        assertThat(message.getSubject()).contains("Reset");
        assertThat(message.getText()).contains("http://localhost:8080/reset-password?token=opaque-token-123");
    }

    @Test
    @DisplayName("buildResetLink appends token as query param when base URL already has params")
    void buildResetLink_withExistingQueryParams_appendsToken() {
        AuthTokenProperties properties = new AuthTokenProperties(
                "https://auth.test",
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                "k1",
                Duration.ofHours(1),
                "http://app/reset?lang=en",
                "http://localhost:8082",
                "dev-internal-secret");
        SmtpPasswordResetNotifier customNotifier =
                new SmtpPasswordResetNotifier(mailSender, properties, "noreply@snow-resorts.local");

        assertThat(customNotifier.buildResetLink("abc"))
                .isEqualTo("http://app/reset?lang=en&token=abc");
    }
}
