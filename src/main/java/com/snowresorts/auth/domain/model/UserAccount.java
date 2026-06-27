package com.snowresorts.auth.domain.model;

import java.util.UUID;

/** Authentication identity: credentials and account status. Domain model, never exposed on the API. */
public record UserAccount(UUID id, String email, String passwordHash, boolean enabled) {
}
