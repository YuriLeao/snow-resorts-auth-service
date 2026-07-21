package com.snowresorts.auth.application;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * In-memory rate limits for authentication endpoints.
 * <ul>
 *   <li>IP: 30 requests / minute</li>
 *   <li>Account (email): 10 requests / 15 minutes</li>
 * </ul>
 */
@Component
public class AuthRateLimiter {

    private static final int IP_LIMIT = 30;
    private static final long IP_WINDOW_MS = 60_000L;
    private static final int ACCOUNT_LIMIT = 10;
    private static final long ACCOUNT_WINDOW_MS = 15 * 60_000L;

    private final Map<String, Window> ipWindows = new ConcurrentHashMap<>();
    private final Map<String, Window> accountWindows = new ConcurrentHashMap<>();

    public boolean tryConsumeIp(String clientIp) {
        String key = clientIp == null || clientIp.isBlank() ? "unknown" : clientIp.trim();
        return tryConsume(ipWindows, key, IP_LIMIT, IP_WINDOW_MS);
    }

    public boolean tryConsumeAccount(String normalizedEmail) {
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            return true;
        }
        return tryConsume(accountWindows, normalizedEmail, ACCOUNT_LIMIT, ACCOUNT_WINDOW_MS);
    }

    private static boolean tryConsume(Map<String, Window> windows, String key, int limit, long windowMs) {
        Instant now = Instant.now();
        Window window = windows.computeIfAbsent(key, ignored -> new Window(now, 0));
        synchronized (window) {
            if (now.toEpochMilli() - window.startedAt.toEpochMilli() >= windowMs) {
                window.startedAt = now;
                window.count = 0;
            }
            if (window.count >= limit) {
                return false;
            }
            window.count++;
            return true;
        }
    }

    private static final class Window {
        private Instant startedAt;
        private int count;

        private Window(Instant startedAt, int count) {
            this.startedAt = startedAt;
            this.count = count;
        }
    }
}
