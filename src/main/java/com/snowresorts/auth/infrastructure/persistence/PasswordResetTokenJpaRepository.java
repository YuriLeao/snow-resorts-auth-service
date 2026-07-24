package com.snowresorts.auth.infrastructure.persistence;

import jakarta.transaction.Transactional;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetTokenJpaRepository extends JpaRepository<PasswordResetTokenEntity, UUID> {

    Optional<PasswordResetTokenEntity> findByTokenHash(String tokenHash);

    @Modifying
    @Transactional
    @Query("update PasswordResetTokenEntity t set t.used = true where t.userId = :userId and t.used = false")
    void invalidateUnusedForUser(@Param("userId") UUID userId);
}
