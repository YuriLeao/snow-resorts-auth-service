package com.snowresorts.auth.infrastructure.security;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.security.logging.StructuredLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/** Fails fast when the default internal API secret is used outside local/test. */
@Component
public class InternalApiSecretGuard implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(InternalApiSecretGuard.class);
    private static final String DEFAULT_SECRET = "dev-internal-secret";

    private final AuthTokenProperties properties;
    private final Environment environment;

    public InternalApiSecretGuard(AuthTokenProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments args) {
        boolean localOrTest = environment.acceptsProfiles(Profiles.of("local", "test"));
        if (!localOrTest && DEFAULT_SECRET.equals(properties.internalApiSecret())) {
            throw new IllegalStateException(
                    "INTERNAL_API_SECRET must be set to a strong value outside local/test profiles");
        }
        if (localOrTest && DEFAULT_SECRET.equals(properties.internalApiSecret())) {
            StructuredLogger.of(log).warn("internal_api_secret", "accepted", "default_secret");
        }
    }
}
