package com.snowresorts.auth.infrastructure.persistence;

import com.snowresorts.auth.domain.model.RefreshToken;
import com.snowresorts.auth.domain.port.RefreshTokens;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRepositoryAdapter implements RefreshTokens {

    private final RefreshTokenJpaRepository jpaRepository;

    public RefreshTokenRepositoryAdapter(RefreshTokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public RefreshToken save(UUID userId, String tokenHash, Instant expiresAt) {
        RefreshTokenEntity entity = new RefreshTokenEntity(
                UUID.randomUUID(), userId, tokenHash, expiresAt, false, Instant.now());
        return toDomain(jpaRepository.save(entity));
    }

    @Override
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return jpaRepository.findByTokenHash(tokenHash).map(this::toDomain);
    }

    @Override
    public void revoke(UUID tokenId) {
        jpaRepository.findById(tokenId).ifPresent(entity -> {
            entity.setRevoked(true);
            jpaRepository.save(entity);
        });
    }

    @Override
    public void revokeAllForUser(UUID userId) {
        jpaRepository.revokeAllForUser(userId);
    }

    private RefreshToken toDomain(RefreshTokenEntity entity) {
        return new RefreshToken(entity.getId(), entity.getUserId(), entity.getTokenHash(),
                entity.getExpiresAt(), entity.isRevoked(), entity.getCreatedAt());
    }
}
