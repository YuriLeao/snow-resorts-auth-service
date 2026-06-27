package com.snowresorts.auth.infrastructure.persistence;

import com.snowresorts.auth.domain.model.UserAccount;
import com.snowresorts.auth.domain.port.UserAccounts;
import com.snowresorts.security.error.ResourceNotFoundException;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class UserAccountRepositoryAdapter implements UserAccounts {

    private final UserAccountJpaRepository jpaRepository;

    public UserAccountRepositoryAdapter(UserAccountJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<UserAccount> findByEmail(String email) {
        return jpaRepository.findByEmail(email).map(this::toDomain);
    }

    @Override
    public Optional<UserAccount> findById(UUID id) {
        return jpaRepository.findById(id).map(this::toDomain);
    }

    @Override
    public UserAccount create(String email, String passwordHash, boolean enabled) {
        UserAccountEntity entity = new UserAccountEntity(
                UUID.randomUUID(), email, passwordHash, enabled, Instant.now());
        return toDomain(jpaRepository.save(entity));
    }

    @Override
    public void updatePassword(UUID userId, String newPasswordHash) {
        UserAccountEntity entity = jpaRepository.findById(userId)
                .orElseThrow(() -> ResourceNotFoundException.of("UserAccount", userId));
        entity.setPasswordHash(newPasswordHash);
        jpaRepository.save(entity);
    }

    private UserAccount toDomain(UserAccountEntity entity) {
        return new UserAccount(entity.getId(), entity.getEmail(), entity.getPasswordHash(), entity.isEnabled());
    }
}
