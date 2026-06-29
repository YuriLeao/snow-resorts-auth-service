package com.snowresorts.auth.infrastructure.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.snowresorts.auth.application.AuthTokenProperties;
import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.internet.MimeMessage;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

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
    void sendPasswordReset_withToken_sendsEmailWithResetLink() throws Exception {
        JavaMailSenderImpl realSender = new JavaMailSenderImpl();
        when(mailSender.createMimeMessage()).thenAnswer(invocation -> realSender.createMimeMessage());

        // Act
        notifier.sendPasswordReset("rider@snow-resorts.com", "opaque-token-123");

        // Assert
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        MimeMessage message = captor.getValue();
        message.saveChanges();
        assertThat(message.getAllRecipients()[0].toString()).isEqualTo("rider@snow-resorts.com");
        assertThat(message.getFrom()[0].toString()).isEqualTo("noreply@snow-resorts.local");
        assertThat(message.getSubject()).contains("Reset");

        String resetUrl = "http://localhost:8080/reset-password?token=opaque-token-123";
        String plainText = extractPartContent(message, "text/plain");
        String htmlText = extractPartContent(message, "text/html");
        assertThat(plainText).isNotNull().contains(resetUrl);
        assertThat(htmlText).isNotNull()
                .contains("<a href=\"" + resetUrl + "\">Reset your password</a>")
                .contains("font-family: -apple-system")
                .contains("cid:appIcon");
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

    private static String extractPartContent(MimeMessage message, String mimeType) throws Exception {
        return findPartContent(message.getContent(), mimeType);
    }

    private static String findPartContent(Object content, String mimeType) throws Exception {
        if (!(content instanceof Multipart multipart)) {
            return null;
        }
        for (int i = 0; i < multipart.getCount(); i++) {
            BodyPart part = multipart.getBodyPart(i);
            Object partContent = part.getContent();
            if (partContent instanceof Multipart) {
                String found = findPartContent(partContent, mimeType);
                if (found != null) {
                    return found;
                }
            } else if (part.isMimeType(mimeType)) {
                return partContent.toString();
            }
        }
        return null;
    }
}
