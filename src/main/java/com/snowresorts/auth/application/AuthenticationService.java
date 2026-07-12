package com.snowresorts.auth.application;

import com.snowresorts.auth.domain.model.IssuedAccessToken;
import com.snowresorts.auth.domain.model.RefreshToken;
import com.snowresorts.auth.domain.model.TokenPair;
import com.snowresorts.auth.domain.model.UserAccount;
import com.snowresorts.auth.domain.port.AccessTokenIssuer;
import com.snowresorts.auth.domain.port.ProfileBootstrap;
import com.snowresorts.auth.domain.port.RefreshTokens;
import com.snowresorts.auth.domain.port.UserAccounts;
import com.snowresorts.security.error.ConflictException;
import com.snowresorts.security.error.UnauthorizedException;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Core authentication use cases: password login, refresh-token rotation and logout.
 * Refresh tokens are single-use; on every refresh the presented token is revoked and a new
 * one is issued. Presenting an already-revoked token is treated as a reuse/theft signal and
 * revokes the user's entire token family.
 */
@Service
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserAccounts userAccounts;
    private final RefreshTokens refreshTokens;
    private final AccessTokenIssuer accessTokenIssuer;
    private final ProfileBootstrap profileBootstrap;
    private final PasswordEncoder passwordEncoder;
    private final Duration refreshTokenTtl;

    public AuthenticationService(UserAccounts userAccounts,
                                 RefreshTokens refreshTokens,
                                 AccessTokenIssuer accessTokenIssuer,
                                 ProfileBootstrap profileBootstrap,
                                 PasswordEncoder passwordEncoder,
                                 AuthTokenProperties properties) {
        this.userAccounts = userAccounts;
        this.refreshTokens = refreshTokens;
        this.accessTokenIssuer = accessTokenIssuer;
        this.profileBootstrap = profileBootstrap;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenTtl = properties.refreshTokenTtl();
    }

    /**
     * Registers a new account and immediately issues a token pair (auto-login), reusing the
     * same issuance path as {@link #login}. The email is normalized and must be unique.
     *
     * @throws ConflictException if an account with the same (normalized) email already exists
     */
    @Transactional
    public TokenPair register(String email, String rawPassword, String username, String displayName) {
        String normalizedEmail = normalize(email);
        if (userAccounts.findByEmail(normalizedEmail).isPresent()) {
            throw new ConflictException("An account with this email already exists.");
        }

        profileBootstrap.ensureUsernameAvailable(username);

        String passwordHash = passwordEncoder.encode(rawPassword);
        UserAccount account = userAccounts.create(normalizedEmail, passwordHash, true);
        log.info("Registered new account {}", account.id());
        profileBootstrap.bootstrapProfile(account.id(), account.email(), username, displayName.trim());
        return issueTokens(account);
    }

    @Transactional
    public TokenPair login(String email, String rawPassword) {
        UserAccount account = userAccounts.findByEmail(normalize(email))
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password."));

        if (!passwordEncoder.matches(rawPassword, account.passwordHash())) {
            log.info("Failed login attempt for account {}", account.id());
            throw new UnauthorizedException("Invalid email or password.");
        }
        if (!account.enabled()) {
            throw new UnauthorizedException("Account is disabled.");
        }

        log.info("Successful login for account {}", account.id());
        return issueTokens(account);
    }

    @Transactional
    public TokenPair refresh(String rawRefreshToken) {
        String hash = RefreshTokenCodec.hash(rawRefreshToken);
        RefreshToken stored = refreshTokens.findByTokenHash(hash)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token."));

        Instant now = Instant.now();
        if (stored.revoked()) {
            // Token reuse after rotation — likely theft. Revoke the whole family.
            log.warn("Detected reuse of a revoked refresh token for account {}; revoking all sessions",
                    stored.userId());
            refreshTokens.revokeAllForUser(stored.userId());
            throw new UnauthorizedException("Invalid refresh token.");
        }
        if (!stored.isActive(now)) {
            throw new UnauthorizedException("Refresh token has expired.");
        }

        UserAccount account = userAccounts.findById(stored.userId())
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token."));

        refreshTokens.revoke(stored.id());
        return issueTokens(account);
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        refreshTokens.findByTokenHash(RefreshTokenCodec.hash(rawRefreshToken))
                .ifPresent(token -> refreshTokens.revoke(token.id()));
    }

    private TokenPair issueTokens(UserAccount account) {
        IssuedAccessToken access = accessTokenIssuer.issue(account);
        String rawRefresh = RefreshTokenCodec.newRawToken();
        refreshTokens.save(account.id(), RefreshTokenCodec.hash(rawRefresh),
                Instant.now().plus(refreshTokenTtl));
        return TokenPair.bearer(access.value(), rawRefresh, access.expiresInSeconds());
    }

    private String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
