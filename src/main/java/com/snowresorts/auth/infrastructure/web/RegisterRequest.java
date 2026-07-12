package com.snowresorts.auth.infrastructure.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Signup payload. Email and username uniqueness are enforced by downstream services. */
public record RegisterRequest(
        @NotBlank(message = "email is required")
        @Email(message = "must be a well-formed email address")
        @Size(max = 320, message = "email is too long")
        String email,

        @NotBlank(message = "password is required")
        @Size(min = 8, max = 200, message = "password must be between 8 and 200 characters")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).*$",
                message = "password must contain at least one letter, one digit, and one special character")
        String password,

        @NotBlank(message = "username is required")
        @Size(min = 3, max = 20, message = "username must be between 3 and 20 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "username may only contain letters, numbers and underscores")
        String username,

        @NotBlank(message = "displayName is required")
        @Size(max = 100, message = "displayName must be at most 100 characters")
        String displayName) {
}
