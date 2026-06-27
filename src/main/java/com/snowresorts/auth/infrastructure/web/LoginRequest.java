package com.snowresorts.auth.infrastructure.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "email is required")
        @Email(message = "must be a well-formed email address")
        String email,

        @NotBlank(message = "password is required")
        @Size(max = 200, message = "password is too long")
        String password) {
}
