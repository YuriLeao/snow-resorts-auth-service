package com.snowresorts.auth.infrastructure.notification;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class LoggingPasswordResetNotifierTest {

    @Test
    @DisplayName("sendPasswordReset never logs the raw reset token")
    void sendPasswordReset_doesNotLogRawToken() {
        Logger logger = (Logger) LoggerFactory.getLogger(LoggingPasswordResetNotifier.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        String secretToken = "super-secret-reset-token-xyz";
        new LoggingPasswordResetNotifier().sendPasswordReset("user@example.com", secretToken);

        String joined = appender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .reduce("", (a, b) -> a + "\n" + b);
        assertThat(joined).doesNotContain(secretToken);
        assertThat(joined).doesNotContain("super-secret");
        logger.detachAppender(appender);
    }
}
