package com.snowresorts.auth.application;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT/token configuration.
 *
 * <pre>
 * snow:
 *   auth:
 *     issuer: https://auth.snow-resorts.local
 *     access-token-ttl: 15m
 *     refresh-token-ttl: 30d
 *     password-reset-ttl: 1h
 *     key-id: snow-auth-key
 *     password-reset-base-url: http://localhost:8080/reset-password
 *     user-service-url: http://localhost:8082
 *     internal-api-secret: ${INTERNAL_API_SECRET:dev-internal-secret}
 * </pre>
 */
@ConfigurationProperties(prefix = "snow.auth")
public record AuthTokenProperties(
        String issuer,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String keyId,
        Duration passwordResetTtl,
        String passwordResetBaseUrl,
        String userServiceUrl,
        String internalApiSecret) {

    public AuthTokenProperties {
        if (issuer == null || issuer.isBlank()) {
            issuer = "https://auth.snow-resorts.local";
        }
        if (accessTokenTtl == null) {
            accessTokenTtl = Duration.ofMinutes(15);
        }
        if (refreshTokenTtl == null) {
            refreshTokenTtl = Duration.ofDays(30);
        }
        if (keyId == null || keyId.isBlank()) {
            keyId = "snow-auth-key";
        }
        if (passwordResetTtl == null) {
            passwordResetTtl = Duration.ofHours(1);
        }
        if (passwordResetBaseUrl == null || passwordResetBaseUrl.isBlank()) {
            passwordResetBaseUrl = "http://localhost:8080/reset-password";
        }
        if (userServiceUrl == null || userServiceUrl.isBlank()) {
            userServiceUrl = "http://localhost:8082";
        }
        if (internalApiSecret == null || internalApiSecret.isBlank()) {
            internalApiSecret = "dev-internal-secret";
        }
    }
}
