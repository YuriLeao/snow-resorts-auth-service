package com.snowresorts.auth.infrastructure.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Signup payload. Email uniqueness is enforced by the service; format/strength is validated here. */
public record RegisterRequest(
        @NotBlank(message = "email is required")
        @Email(message = "must be a well-formed email address")
        @Size(max = 320, message = "email is too long")
        String email,

        @NotBlank(message = "password is required")
        @Size(min = 8, max = 200, message = "password must be between 8 and 200 characters")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).*$",
                message = "password must contain at least one letter and one digit")
        String password) {
}
