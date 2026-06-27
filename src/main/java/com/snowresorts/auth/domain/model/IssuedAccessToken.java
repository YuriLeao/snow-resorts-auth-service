package com.snowresorts.auth.domain.model;

/** A signed access token together with its lifetime, returned by the {@code AccessTokenIssuer} port. */
public record IssuedAccessToken(String value, long expiresInSeconds) {
}
