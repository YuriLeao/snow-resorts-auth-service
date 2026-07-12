package com.snowresorts.auth.domain.port;

import java.util.UUID;

/**
 * Outbound port that asks user-service to create a default profile after registration.
 * Failures are logged but must not roll back account creation, except username conflicts
 * which must propagate to the caller.
 */
public interface ProfileBootstrap {

    /** Validates format and availability before account creation. */
    void ensureUsernameAvailable(String username);

    void bootstrapProfile(UUID userId, String email, String username, String displayName);
}
