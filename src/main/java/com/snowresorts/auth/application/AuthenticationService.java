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
import com.snowresorts.security.error.TooManyRequestsException;
import com.snowresorts.security.jwt.AccessTokenRevocationStore;
import com.snowresorts.security.logging.StructuredLogger;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
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

    private static final String GENERIC_REGISTER_ERROR = "Registration could not be completed.";
    private static final String GENERIC_LOGIN_ERROR = "Invalid email or password.";

    private final UserAccounts userAccounts;
    private final RefreshTokens refreshTokens;
    private final AccessTokenIssuer accessTokenIssuer;
    private final ProfileBootstrap profileBootstrap;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenRevocationStore accessTokenRevocationStore;
    private final AuthRateLimiter rateLimiter;
    private final Duration refreshTokenTtl;
    private final Duration accessTokenTtl;
    /** Bcrypt of a fixed string — used only to equalise login timing when the email is unknown. */
    private final String dummyPasswordHash;

    public AuthenticationService(UserAccounts userAccounts,
                                 RefreshTokens refreshTokens,
                                 AccessTokenIssuer accessTokenIssuer,
                                 ProfileBootstrap profileBootstrap,
                                 PasswordEncoder passwordEncoder,
                                 AccessTokenRevocationStore accessTokenRevocationStore,
                                 AuthRateLimiter rateLimiter,
                                 AuthTokenProperties properties) {
        this.userAccounts = userAccounts;
        this.refreshTokens = refreshTokens;
        this.accessTokenIssuer = accessTokenIssuer;
        this.profileBootstrap = profileBootstrap;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenRevocationStore = accessTokenRevocationStore;
        this.rateLimiter = rateLimiter;
        this.refreshTokenTtl = properties.refreshTokenTtl();
        this.accessTokenTtl = properties.accessTokenTtl();
        this.dummyPasswordHash = passwordEncoder.encode("!snow-resorts-timing-dummy!");
    }

    /**
     * Registers a new account and immediately issues a token pair (auto-login).
     * Conflict messages are intentionally generic to avoid account enumeration.
     */
    @Transactional
    public TokenPair register(String email, String rawPassword, String username, String displayName) {
        String normalizedEmail = normalize(email);
        if (userAccounts.findByEmail(normalizedEmail).isPresent()) {
            passwordEncoder.encode(rawPassword);
            throw new ConflictException(GENERIC_REGISTER_ERROR);
        }

        try {
            profileBootstrap.ensureUsernameAvailable(username);
        } catch (ConflictException ex) {
            throw new ConflictException(GENERIC_REGISTER_ERROR);
        }

        String passwordHash = passwordEncoder.encode(rawPassword);
        UserAccount account = userAccounts.create(normalizedEmail, passwordHash, true);
        StructuredLogger.of(log).info("register", "succeeded", "account_created",
                "user_id", account.id());
        try {
            profileBootstrap.bootstrapProfile(account.id(), account.email(), username, displayName.trim());
        } catch (ConflictException ex) {
            throw new ConflictException(GENERIC_REGISTER_ERROR);
        }
        return issueTokens(account);
    }

    @Transactional
    public TokenPair login(String email, String rawPassword) {
        String normalizedEmail = normalize(email);
        // IP limit is enforced by AuthRateLimitFilter; account limit lives here.
        if (!rateLimiter.tryConsumeAccount(normalizedEmail)) {
            throw new TooManyRequestsException("Too many authentication attempts. Try again later.");
        }

        UserAccount account = userAccounts.findByEmail(normalizedEmail).orElse(null);
        String hashToCheck = account != null ? account.passwordHash() : dummyPasswordHash;
        boolean passwordMatches = passwordEncoder.matches(rawPassword, hashToCheck);

        if (account == null || !passwordMatches || !account.enabled()) {
            if (account != null) {
                StructuredLogger.of(log).info("login", "denied", "invalid_credentials",
                        "user_id", account.id());
            }
            throw new UnauthorizedException(GENERIC_LOGIN_ERROR);
        }

        StructuredLogger.of(log).info("login", "succeeded", "ok", "user_id", account.id());
        return issueTokens(account);
    }

    @Transactional
    public TokenPair refresh(String rawRefreshToken) {
        String hash = RefreshTokenCodec.hash(rawRefreshToken);
        RefreshToken stored = refreshTokens.findByTokenHash(hash)
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token."));

        Instant now = Instant.now();
        if (stored.revoked()) {
            StructuredLogger.of(log).warn("refresh", "denied", "token_reuse",
                    "user_id", stored.userId());
            refreshTokens.revokeAllForUser(stored.userId());
            accessTokenRevocationStore.revokeAllIssuedAtOrBefore(
                    stored.userId(), now, accessTokenTtl);
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

    /**
     * Revokes the presented refresh-token family and denylists access tokens. Public endpoint —
     * the refresh token is the primary credential; when it is missing/invalid but a Bearer access
     * token is presented, that token's subject is still revoked (session kill).
     */
    @Transactional
    public void logout(String rawRefreshToken, String accessTokenJti, UUID accessTokenUserId) {
        Instant now = Instant.now();
        AtomicBoolean refreshRevoked = new AtomicBoolean(false);
        refreshTokens.findByTokenHash(RefreshTokenCodec.hash(rawRefreshToken)).ifPresent(token -> {
            refreshTokens.revokeAllForUser(token.userId());
            accessTokenRevocationStore.revokeAllIssuedAtOrBefore(token.userId(), now, accessTokenTtl);
            refreshRevoked.set(true);
            StructuredLogger.of(log).info("logout", "succeeded", "refresh_revoked",
                    "user_id", token.userId());
        });
        if (!refreshRevoked.get() && accessTokenUserId != null) {
            accessTokenRevocationStore.revokeAllIssuedAtOrBefore(accessTokenUserId, now, accessTokenTtl);
            StructuredLogger.of(log).info("logout", "succeeded", "access_revoked",
                    "user_id", accessTokenUserId);
        }
        if (accessTokenJti != null && !accessTokenJti.isBlank()) {
            accessTokenRevocationStore.revokeJti(accessTokenJti, accessTokenTtl);
        }
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
