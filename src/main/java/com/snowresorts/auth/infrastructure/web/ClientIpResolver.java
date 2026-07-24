package com.snowresorts.auth.infrastructure.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the client IP for rate limiting from {@code remoteAddr} only.
 * Does not trust {@code X-Forwarded-For} / {@code X-Real-IP} (spoofable by clients);
 * nginx strips inbound XFF so the peer address is the edge hop.
 */
final class ClientIpResolver {

    private ClientIpResolver() {
    }

    static String resolve(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        if (remote != null && !remote.isBlank()) {
            return remote.trim();
        }
        return "unknown";
    }
}
