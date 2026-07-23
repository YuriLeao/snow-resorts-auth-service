package com.snowresorts.auth.infrastructure.web;

import com.snowresorts.auth.application.AuthRateLimiter;
import com.snowresorts.security.logging.StructuredLogger;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * IP-based rate limit on public auth endpoints (login/register/forgot/reset/refresh).
 * Account-level limits for login are applied inside {@code AuthenticationService}.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class AuthRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthRateLimitFilter.class);

    private final AuthRateLimiter rateLimiter;

    public AuthRateLimitFilter(AuthRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null || !"POST".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        return !(path.endsWith("/auth/login")
                || path.endsWith("/auth/register")
                || path.endsWith("/auth/refresh")
                || path.endsWith("/auth/forgot-password")
                || path.endsWith("/auth/reset-password"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String ip = ClientIpResolver.resolve(request);
        if (!rateLimiter.tryConsumeIp(ip)) {
            StructuredLogger.of(log).warn("auth_rate_limit", "denied", "ip_limit_exceeded",
                    "path", request.getRequestURI());
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            response.getWriter().write(
                    "{\"title\":\"Too Many Requests\",\"status\":429,"
                            + "\"detail\":\"Too many authentication attempts. Try again later.\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
