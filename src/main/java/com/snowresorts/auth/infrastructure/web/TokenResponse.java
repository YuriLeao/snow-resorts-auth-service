package com.snowresorts.auth.infrastructure.web;

import com.snowresorts.auth.domain.model.TokenPair;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType) {

    public static TokenResponse from(TokenPair pair) {
        return new TokenResponse(pair.accessToken(), pair.refreshToken(),
                pair.accessTokenExpiresInSeconds(), pair.tokenType());
    }
}
