package com.snowresorts.auth.infrastructure.web;

import com.snowresorts.auth.application.AuthenticationService;
import com.snowresorts.auth.application.PasswordResetService;
import com.snowresorts.auth.domain.model.TokenPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.text.ParseException;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/snow-resort-service/v1/auth")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final PasswordResetService passwordResetService;

    public AuthController(AuthenticationService authenticationService,
                         PasswordResetService passwordResetService) {
        this.authenticationService = authenticationService;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenResponse register(@Valid @RequestBody RegisterRequest request) {
        TokenPair pair = authenticationService.register(
                request.email(), request.password(), request.username(), request.displayName());
        return TokenResponse.from(pair);
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        TokenPair pair = authenticationService.login(request.email(), request.password());
        return TokenResponse.from(pair);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        TokenPair pair = authenticationService.refresh(request.refreshToken());
        return TokenResponse.from(pair);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshRequest request, HttpServletRequest httpRequest) {
        AccessTokenHints hints = extractAccessTokenHints(httpRequest);
        authenticationService.logout(request.refreshToken(), hints.jti(), hints.userId());
    }

    @PostMapping("/forgot-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.requestReset(request.email());
    }

    @PostMapping("/reset-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request.token(), request.newPassword());
    }

    private static AccessTokenHints extractAccessTokenHints(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return AccessTokenHints.none();
        }
        String token = authorization.substring("Bearer ".length()).trim();
        if (token.isEmpty()) {
            return AccessTokenHints.none();
        }
        try {
            JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
            UUID userId = null;
            if (claims.getSubject() != null) {
                try {
                    userId = UUID.fromString(claims.getSubject());
                } catch (IllegalArgumentException ignored) {
                    // ignore malformed sub
                }
            }
            return new AccessTokenHints(claims.getJWTID(), userId);
        } catch (ParseException ex) {
            return AccessTokenHints.none();
        }
    }

    private record AccessTokenHints(String jti, UUID userId) {
        static AccessTokenHints none() {
            return new AccessTokenHints(null, null);
        }
    }
}
