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
 *     audience: snow-resorts-api
 *     access-token-ttl: 15m
 *     refresh-token-ttl: 30d
 *     password-reset-ttl: 1h
 *     key-id: snow-auth-key
 *     signing-key-pem: ${JWT_SECRET:}
 *     previous-signing-key-pem: ${JWT_PREVIOUS_SECRET:}
 *     previous-key-id: snow-auth-key-previous
 *     password-reset-base-url: http://localhost:8080/reset-password
 *     user-service-url: http://localhost:8082
 *     internal-api-secret: ${INTERNAL_API_SECRET:dev-internal-secret}
 * </pre>
 */
@ConfigurationProperties(prefix = "snow.auth")
public record AuthTokenProperties(
        String issuer,
        String audience,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String keyId,
        Duration passwordResetTtl,
        String passwordResetBaseUrl,
        String userServiceUrl,
        String internalApiSecret,
        String signingKeyPem,
        String previousSigningKeyPem,
        String previousKeyId) {

    public AuthTokenProperties {
        if (issuer == null || issuer.isBlank()) {
            issuer = "https://auth.snow-resorts.local";
        }
        if (audience == null || audience.isBlank()) {
            audience = "snow-resorts-api";
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
        if (signingKeyPem != null && signingKeyPem.isBlank()) {
            signingKeyPem = null;
        }
        if (previousSigningKeyPem != null && previousSigningKeyPem.isBlank()) {
            previousSigningKeyPem = null;
        }
        if (previousKeyId != null && previousKeyId.isBlank()) {
            previousKeyId = null;
        }
    }
}
