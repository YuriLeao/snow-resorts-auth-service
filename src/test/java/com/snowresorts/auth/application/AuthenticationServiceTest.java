package com.snowresorts.auth.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    private static final UUID USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @Mock
    private UserAccounts userAccounts;
    @Mock
    private RefreshTokens refreshTokens;
    @Mock
    private AccessTokenIssuer accessTokenIssuer;
    @Mock
    private ProfileBootstrap profileBootstrap;
    @Mock
    private PasswordEncoder passwordEncoder;

    private AuthenticationService service;

    @BeforeEach
    void setUp() {
        AuthTokenProperties props = new AuthTokenProperties(
                "https://auth.test", Duration.ofMinutes(15), Duration.ofDays(30), "k1", Duration.ofHours(1),
                null, null, null);
        service = new AuthenticationService(userAccounts, refreshTokens, accessTokenIssuer,
                profileBootstrap, passwordEncoder, props);
    }

    private UserAccount enabledAccount() {
        return new UserAccount(USER_ID, "demo@snow-resorts.com", "stored-hash", true);
    }

    @Test
    @DisplayName("login with valid credentials issues a bearer token pair and persists a refresh hash")
    void login_withValidCredentials_returnsTokenPair() {
        // Arrange
        UserAccount account = enabledAccount();
        when(userAccounts.findByEmail("demo@snow-resorts.com")).thenReturn(Optional.of(account));
        when(passwordEncoder.matches("Password123!", "stored-hash")).thenReturn(true);
        when(accessTokenIssuer.issue(account)).thenReturn(new IssuedAccessToken("access.jwt", 900));

        // Act
        TokenPair pair = service.login("Demo@Snow-Resorts.com", "Password123!");

        // Assert
        assertThat(pair.accessToken()).isEqualTo("access.jwt");
        assertThat(pair.tokenType()).isEqualTo("Bearer");
        assertThat(pair.accessTokenExpiresInSeconds()).isEqualTo(900);
        assertThat(pair.refreshToken()).isNotBlank();

        ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
        verify(refreshTokens).save(eq(USER_ID), hashCaptor.capture(), any(Instant.class));
        // Stored value is a hash, never the raw token handed to the client.
        assertThat(hashCaptor.getValue()).isNotEqualTo(pair.refreshToken());
        assertThat(hashCaptor.getValue()).isEqualTo(RefreshTokenCodec.hash(pair.refreshToken()));
    }

    @Test
    @DisplayName("register with a new email normalizes it, hashes the password and issues tokens")
    void register_withNewEmail_createsAccountAndIssuesTokens() {
        // Arrange
        UserAccount created = new UserAccount(USER_ID, "newrider@snow-resorts.com", "encoded-hash", true);
        when(userAccounts.findByEmail("newrider@snow-resorts.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Password123!")).thenReturn("encoded-hash");
        when(userAccounts.create("newrider@snow-resorts.com", "encoded-hash", true)).thenReturn(created);
        when(accessTokenIssuer.issue(created)).thenReturn(new IssuedAccessToken("access.jwt", 900));

        // Act
        TokenPair pair = service.register("  NewRider@Snow-Resorts.com  ", "Password123!", "newrider", "New Rider");

        // Assert
        assertThat(pair.accessToken()).isEqualTo("access.jwt");
        assertThat(pair.tokenType()).isEqualTo("Bearer");
        assertThat(pair.refreshToken()).isNotBlank();
        verify(profileBootstrap).ensureUsernameAvailable("newrider");
        verify(userAccounts).create("newrider@snow-resorts.com", "encoded-hash", true);
        verify(profileBootstrap).bootstrapProfile(USER_ID, "newrider@snow-resorts.com", "newrider", "New Rider");
        verify(refreshTokens).save(eq(USER_ID), any(), any(Instant.class));
    }

    @Test
    @DisplayName("register with a taken username returns 409 and never creates an account")
    void register_withTakenUsername_throwsConflict() {
        when(userAccounts.findByEmail("newrider@snow-resorts.com")).thenReturn(Optional.empty());
        org.mockito.Mockito.doThrow(new ConflictException("That username is already taken."))
                .when(profileBootstrap).ensureUsernameAvailable("taken");

        assertThatThrownBy(() -> service.register("newrider@snow-resorts.com", "Password123!", "taken", "Rider"))
                .isInstanceOf(ConflictException.class);

        verify(userAccounts, never()).create(any(), any(), anyBoolean());
        verify(profileBootstrap, never()).bootstrapProfile(any(), any(), any(), any());
        verify(refreshTokens, never()).save(any(), any(), any());
    }

    @Test
    @DisplayName("register with an already-registered email returns 409 and never creates an account")
    void register_withDuplicateEmail_throwsConflict() {
        when(userAccounts.findByEmail("demo@snow-resorts.com")).thenReturn(Optional.of(enabledAccount()));

        assertThatThrownBy(() -> service.register("Demo@Snow-Resorts.com", "Password123!", "demo", "Demo"))
                .isInstanceOf(ConflictException.class);

        verify(userAccounts, never()).create(any(), any(), anyBoolean());
        verify(profileBootstrap, never()).ensureUsernameAvailable(any());
        verify(profileBootstrap, never()).bootstrapProfile(any(), any(), any(), any());
        verify(refreshTokens, never()).save(any(), any(), any());
    }

    @Test
    @DisplayName("login with wrong password returns 401 without leaking which factor failed")
    void login_withWrongPassword_throwsUnauthorized() {
        when(userAccounts.findByEmail("demo@snow-resorts.com")).thenReturn(Optional.of(enabledAccount()));
        when(passwordEncoder.matches("bad", "stored-hash")).thenReturn(false);

        assertThatThrownBy(() -> service.login("demo@snow-resorts.com", "bad"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessage("Invalid email or password.");

        verify(refreshTokens, never()).save(any(), any(), any());
    }

    @Test
    @DisplayName("login with unknown email returns 401")
    void login_withUnknownEmail_throwsUnauthorized() {
        when(userAccounts.findByEmail("nobody@snow-resorts.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login("nobody@snow-resorts.com", "x"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    @DisplayName("login with a disabled account returns 401")
    void login_withDisabledAccount_throwsUnauthorized() {
        UserAccount disabled = new UserAccount(USER_ID, "demo@snow-resorts.com", "stored-hash", false);
        when(userAccounts.findByEmail("demo@snow-resorts.com")).thenReturn(Optional.of(disabled));
        when(passwordEncoder.matches("Password123!", "stored-hash")).thenReturn(true);

        assertThatThrownBy(() -> service.login("demo@snow-resorts.com", "Password123!"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessage("Account is disabled.");
    }

    @Test
    @DisplayName("refresh with a valid token rotates: old token revoked, new pair issued")
    void refresh_withValidToken_rotatesToken() {
        // Arrange
        String rawToken = "valid-raw-refresh-token";
        String hash = RefreshTokenCodec.hash(rawToken);
        UUID tokenId = UUID.randomUUID();
        RefreshToken active = new RefreshToken(tokenId, USER_ID, hash,
                Instant.now().plus(Duration.ofDays(1)), false, Instant.now());
        when(refreshTokens.findByTokenHash(hash)).thenReturn(Optional.of(active));
        when(userAccounts.findById(USER_ID)).thenReturn(Optional.of(enabledAccount()));
        when(accessTokenIssuer.issue(any())).thenReturn(new IssuedAccessToken("new.access", 900));

        // Act
        TokenPair pair = service.refresh(rawToken);

        // Assert
        assertThat(pair.accessToken()).isEqualTo("new.access");
        assertThat(pair.refreshToken()).isNotBlank().isNotEqualTo(rawToken);
        verify(refreshTokens).revoke(tokenId);
        verify(refreshTokens).save(eq(USER_ID), any(), any());
    }

    @Test
    @DisplayName("refresh with an already-revoked token signals reuse and revokes the whole family")
    void refresh_withRevokedToken_revokesAllAndThrows() {
        String rawToken = "stolen-token";
        String hash = RefreshTokenCodec.hash(rawToken);
        RefreshToken revoked = new RefreshToken(UUID.randomUUID(), USER_ID, hash,
                Instant.now().plus(Duration.ofDays(1)), true, Instant.now());
        when(refreshTokens.findByTokenHash(hash)).thenReturn(Optional.of(revoked));

        assertThatThrownBy(() -> service.refresh(rawToken))
                .isInstanceOf(UnauthorizedException.class);

        verify(refreshTokens).revokeAllForUser(USER_ID);
        verify(refreshTokens, never()).save(any(), any(), any());
    }

    @Test
    @DisplayName("refresh with an expired token returns 401")
    void refresh_withExpiredToken_throwsUnauthorized() {
        String rawToken = "expired-token";
        String hash = RefreshTokenCodec.hash(rawToken);
        RefreshToken expired = new RefreshToken(UUID.randomUUID(), USER_ID, hash,
                Instant.now().minus(Duration.ofMinutes(1)), false, Instant.now());
        when(refreshTokens.findByTokenHash(hash)).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> service.refresh(rawToken))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessage("Refresh token has expired.");
    }

    @Test
    @DisplayName("refresh with an unknown token returns 401")
    void refresh_withUnknownToken_throwsUnauthorized() {
        when(refreshTokens.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.refresh("nope"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    @DisplayName("logout revokes the presented refresh token")
    void logout_revokesPresentedToken() {
        String rawToken = "to-logout";
        String hash = RefreshTokenCodec.hash(rawToken);
        UUID tokenId = UUID.randomUUID();
        RefreshToken token = new RefreshToken(tokenId, USER_ID, hash,
                Instant.now().plus(Duration.ofDays(1)), false, Instant.now());
        when(refreshTokens.findByTokenHash(hash)).thenReturn(Optional.of(token));

        service.logout(rawToken);

        verify(refreshTokens).revoke(tokenId);
    }
}
