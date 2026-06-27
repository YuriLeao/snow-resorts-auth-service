package com.snowresorts.auth.application;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.snowresorts.auth.domain.model.PasswordResetToken;
import com.snowresorts.auth.domain.model.UserAccount;
import com.snowresorts.auth.domain.port.PasswordResetNotifier;
import com.snowresorts.auth.domain.port.PasswordResetTokens;
import com.snowresorts.auth.domain.port.RefreshTokens;
import com.snowresorts.auth.domain.port.UserAccounts;
import com.snowresorts.security.error.BadRequestException;
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
class PasswordResetServiceTest {

    private static final UUID USER_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    @Mock
    private UserAccounts userAccounts;
    @Mock
    private PasswordResetTokens passwordResetTokens;
    @Mock
    private PasswordResetNotifier notifier;
    @Mock
    private RefreshTokens refreshTokens;
    @Mock
    private PasswordEncoder passwordEncoder;

    private PasswordResetService service;

    @BeforeEach
    void setUp() {
        AuthTokenProperties props = new AuthTokenProperties(
                "https://auth.test", Duration.ofMinutes(15), Duration.ofDays(30), "k1", Duration.ofHours(1),
                null, null, null);
        service = new PasswordResetService(userAccounts, passwordResetTokens, notifier,
                refreshTokens, passwordEncoder, props);
    }

    private UserAccount account() {
        return new UserAccount(USER_ID, "rider@snow-resorts.com", "stored-hash", true);
    }

    @Test
    @DisplayName("requestReset for an existing account stores only the token hash and notifies the user")
    void requestReset_withExistingEmail_storesHashAndNotifies() {
        // Arrange
        UserAccount account = account();
        when(userAccounts.findByEmail("rider@snow-resorts.com")).thenReturn(Optional.of(account));

        // Act
        service.requestReset("  Rider@Snow-Resorts.com  ");

        // Assert
        ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> rawCaptor = ArgumentCaptor.forClass(String.class);
        verify(passwordResetTokens).save(eq(USER_ID), hashCaptor.capture(), any(Instant.class));
        verify(notifier).sendPasswordReset(eq("rider@snow-resorts.com"), rawCaptor.capture());
        // The persisted value is the hash of the raw token handed to the delivery port, never the raw token.
        org.assertj.core.api.Assertions.assertThat(hashCaptor.getValue())
                .isEqualTo(RefreshTokenCodec.hash(rawCaptor.getValue()))
                .isNotEqualTo(rawCaptor.getValue());
    }

    @Test
    @DisplayName("requestReset for an unknown account does nothing and does not leak existence")
    void requestReset_withUnknownEmail_doesNothing() {
        when(userAccounts.findByEmail("nobody@snow-resorts.com")).thenReturn(Optional.empty());

        service.requestReset("nobody@snow-resorts.com");

        verifyNoInteractions(passwordResetTokens, notifier);
    }

    @Test
    @DisplayName("resetPassword with a valid token sets the new hash, consumes the token and revokes sessions")
    void resetPassword_withValidToken_updatesPasswordAndRevokesSessions() {
        // Arrange
        String rawToken = "valid-reset-token";
        String hash = RefreshTokenCodec.hash(rawToken);
        UUID tokenId = UUID.randomUUID();
        PasswordResetToken token = new PasswordResetToken(tokenId, USER_ID, hash,
                Instant.now().plus(Duration.ofMinutes(30)), false, Instant.now());
        when(passwordResetTokens.findByTokenHash(hash)).thenReturn(Optional.of(token));
        when(passwordEncoder.encode("NewPassword123!")).thenReturn("new-hash");

        // Act
        service.resetPassword(rawToken, "NewPassword123!");

        // Assert
        verify(userAccounts).updatePassword(USER_ID, "new-hash");
        verify(passwordResetTokens).markUsed(tokenId);
        verify(refreshTokens).revokeAllForUser(USER_ID);
    }

    @Test
    @DisplayName("resetPassword with an unknown token returns 400 and changes nothing")
    void resetPassword_withUnknownToken_throwsBadRequest() {
        when(passwordResetTokens.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.resetPassword("nope", "NewPassword123!"))
                .isInstanceOf(BadRequestException.class);

        verify(userAccounts, never()).updatePassword(any(), anyString());
        verify(refreshTokens, never()).revokeAllForUser(any());
    }

    @Test
    @DisplayName("resetPassword with an already-used token returns 400")
    void resetPassword_withUsedToken_throwsBadRequest() {
        String rawToken = "used-token";
        String hash = RefreshTokenCodec.hash(rawToken);
        PasswordResetToken used = new PasswordResetToken(UUID.randomUUID(), USER_ID, hash,
                Instant.now().plus(Duration.ofMinutes(30)), true, Instant.now());
        when(passwordResetTokens.findByTokenHash(hash)).thenReturn(Optional.of(used));

        assertThatThrownBy(() -> service.resetPassword(rawToken, "NewPassword123!"))
                .isInstanceOf(BadRequestException.class);

        verify(userAccounts, never()).updatePassword(any(), anyString());
    }

    @Test
    @DisplayName("resetPassword with an expired token returns 400")
    void resetPassword_withExpiredToken_throwsBadRequest() {
        String rawToken = "expired-token";
        String hash = RefreshTokenCodec.hash(rawToken);
        PasswordResetToken expired = new PasswordResetToken(UUID.randomUUID(), USER_ID, hash,
                Instant.now().minus(Duration.ofMinutes(1)), false, Instant.now());
        when(passwordResetTokens.findByTokenHash(hash)).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> service.resetPassword(rawToken, "NewPassword123!"))
                .isInstanceOf(BadRequestException.class);

        verify(userAccounts, never()).updatePassword(any(), anyString());
    }
}
