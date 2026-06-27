package com.snowresorts.auth.infrastructure.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
        @NotBlank(message = "email is required")
        @Email(message = "must be a well-formed email address")
        String email) {
}
