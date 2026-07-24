package com.snowresorts.auth.infrastructure.persistence;

import com.snowresorts.auth.domain.model.PasswordResetToken;
import com.snowresorts.auth.domain.port.PasswordResetTokens;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class PasswordResetTokenRepositoryAdapter implements PasswordResetTokens {

    private final PasswordResetTokenJpaRepository jpaRepository;

    public PasswordResetTokenRepositoryAdapter(PasswordResetTokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public PasswordResetToken save(UUID userId, String tokenHash, Instant expiresAt) {
        PasswordResetTokenEntity entity = new PasswordResetTokenEntity(
                UUID.randomUUID(), userId, tokenHash, expiresAt, false, Instant.now());
        return toDomain(jpaRepository.save(entity));
    }

    @Override
    public Optional<PasswordResetToken> findByTokenHash(String tokenHash) {
        return jpaRepository.findByTokenHash(tokenHash).map(this::toDomain);
    }

    @Override
    public void markUsed(UUID tokenId) {
        jpaRepository.findById(tokenId).ifPresent(entity -> {
            entity.setUsed(true);
            jpaRepository.save(entity);
        });
    }

    @Override
    public void invalidateUnusedForUser(UUID userId) {
        jpaRepository.invalidateUnusedForUser(userId);
    }

    private PasswordResetToken toDomain(PasswordResetTokenEntity entity) {
        return new PasswordResetToken(entity.getId(), entity.getUserId(), entity.getTokenHash(),
                entity.getExpiresAt(), entity.isUsed(), entity.getCreatedAt());
    }
}
