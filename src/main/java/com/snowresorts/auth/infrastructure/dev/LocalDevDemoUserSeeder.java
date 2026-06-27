package com.snowresorts.auth.infrastructure.dev;

import com.snowresorts.auth.infrastructure.persistence.UserAccountEntity;
import com.snowresorts.auth.infrastructure.persistence.UserAccountJpaRepository;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Ensures the documented local demo account exists after Flyway migrations run.
 * {@code make dev} seeds Postgres before auth-service starts, so the infra seed script
 * often skips {@code auth.users_auth} — this runner closes that gap on the {@code local} profile.
 */
@Component
@Profile("local")
public class LocalDevDemoUserSeeder implements ApplicationRunner {

    static final UUID DEMO_USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    static final String DEMO_EMAIL = "demo@snow-resorts.com";
    static final String DEMO_PASSWORD = "Password123!";

    private static final Logger log = LoggerFactory.getLogger(LocalDevDemoUserSeeder.class);

    private final UserAccountJpaRepository userAccounts;
    private final PasswordEncoder passwordEncoder;

    public LocalDevDemoUserSeeder(UserAccountJpaRepository userAccounts, PasswordEncoder passwordEncoder) {
        this.userAccounts = userAccounts;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userAccounts.findByEmail(DEMO_EMAIL).isPresent()) {
            return;
        }
        userAccounts.save(new UserAccountEntity(
                DEMO_USER_ID,
                DEMO_EMAIL,
                passwordEncoder.encode(DEMO_PASSWORD),
                true,
                Instant.now()));
        log.info("Seeded local demo user {} (password documented in infra README)", DEMO_EMAIL);
    }
}
