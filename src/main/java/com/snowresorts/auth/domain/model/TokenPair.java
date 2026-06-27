package com.snowresorts.auth.domain.model;

/** Result of a successful authentication or refresh: an access token plus a (new) refresh token. */
public record TokenPair(
        String accessToken,
        String refreshToken,
        long accessTokenExpiresInSeconds,
        String tokenType) {

    public static TokenPair bearer(String accessToken, String refreshToken, long expiresInSeconds) {
        return new TokenPair(accessToken, refreshToken, expiresInSeconds, "Bearer");
    }
}
