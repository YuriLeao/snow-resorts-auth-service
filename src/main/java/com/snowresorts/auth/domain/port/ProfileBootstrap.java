package com.snowresorts.auth.domain.port;

import java.util.UUID;

/**
 * Outbound port that asks user-service to create a default profile after registration.
 * Failures are logged but must not roll back account creation.
 */
public interface ProfileBootstrap {

    void bootstrapProfile(UUID userId, String email);
}
