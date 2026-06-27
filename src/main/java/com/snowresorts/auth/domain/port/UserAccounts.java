package com.snowresorts.auth.domain.port;

import com.snowresorts.auth.domain.model.UserAccount;
import java.util.Optional;
import java.util.UUID;

/** Outbound port for reading and writing authentication accounts. */
public interface UserAccounts {

    Optional<UserAccount> findByEmail(String email);

    Optional<UserAccount> findById(UUID id);

    /** Persists a brand-new account. The email is expected to be already normalized and unique. */
    UserAccount create(String email, String passwordHash, boolean enabled);

    /** Replaces the stored password hash for an existing account. */
    void updatePassword(UUID userId, String newPasswordHash);
}
