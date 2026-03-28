package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.model.user.UserStatus;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import com.fivucsas.identity.infrastructure.persistence.mapper.UserMapper;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter bridging the pure domain UserDomainRepository port
 * to the Spring Data JPA repository.
 *
 * Converts between domain User models and JPA User entities using UserMapper.
 * This adapter returns domain models only -- no JPA entity leakage.
 *
 * Follows Hexagonal Architecture: domain defines the port,
 * infrastructure provides the implementation with mapping.
 *
 * For backward compatibility, the existing UserRepositoryAdapter (returning JPA entities)
 * remains available for services not yet migrated to domain models.
 */
@Repository
@RequiredArgsConstructor
public class UserDomainRepositoryAdapter implements UserDomainRepository {

    private final UserRepository jpaRepository;

    @Override
    public User save(User domain) {
        // For updates: load existing JPA entity, apply profile field changes, save.
        // For creates: not yet supported -- use the JPA UserRepository directly.
        // This adapter focuses on read operations; write support is limited to
        // fields with direct setters on the JPA entity (profile, status, biometric).
        if (domain.getId() != null) {
            Optional<com.fivucsas.identity.entity.User> existing = jpaRepository.findById(domain.getId());
            if (existing.isPresent()) {
                com.fivucsas.identity.entity.User jpa = existing.get();
                applyProfileChanges(jpa, domain);
                com.fivucsas.identity.entity.User saved = jpaRepository.save(jpa);
                return UserMapper.toDomain(saved);
            }
        }
        throw new UnsupportedOperationException(
            "Creating new users via UserDomainRepository is not yet supported. " +
            "Use the JPA UserRepository for user creation."
        );
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jpaRepository.findById(id).map(UserMapper::toDomain);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return jpaRepository.findByEmail(email).map(UserMapper::toDomain);
    }

    @Override
    public boolean existsByEmail(String email) {
        return jpaRepository.existsByEmail(email);
    }

    @Override
    public List<User> findByStatus(UserStatus status) {
        com.fivucsas.identity.entity.UserStatus jpaStatus =
            com.fivucsas.identity.entity.UserStatus.valueOf(status.name());
        return UserMapper.toDomainList(jpaRepository.findByStatus(jpaStatus));
    }

    @Override
    public long countByStatus(UserStatus status) {
        com.fivucsas.identity.entity.UserStatus jpaStatus =
            com.fivucsas.identity.entity.UserStatus.valueOf(status.name());
        return jpaRepository.countByStatus(jpaStatus);
    }

    @Override
    public long countByIsBiometricEnrolled(boolean enrolled) {
        return jpaRepository.countByIsBiometricEnrolled(enrolled);
    }

    @Override
    public List<User> searchUsers(String query) {
        return UserMapper.toDomainList(jpaRepository.searchUsers(query));
    }

    @Override
    public Long sumVerificationCount() {
        return jpaRepository.sumVerificationCount();
    }

    @Override
    public List<User> findAll() {
        return UserMapper.toDomainList(jpaRepository.findAll());
    }

    @Override
    public List<User> findAll(int page, int size) {
        return UserMapper.toDomainList(
            jpaRepository.findAllWithRoles(PageRequest.of(page, size)).getContent()
        );
    }

    @Override
    public long count() {
        return jpaRepository.count();
    }

    @Override
    public void deleteById(UUID id) {
        jpaRepository.deleteById(id);
    }

    @Override
    public Optional<User> findByPasswordResetToken(String token) {
        return jpaRepository.findByPasswordResetToken(token).map(UserMapper::toDomain);
    }

    @Override
    public Optional<User> findByEmailVerificationToken(String token) {
        return jpaRepository.findByEmailVerificationToken(token).map(UserMapper::toDomain);
    }

    @Override
    public List<User> findExpiredGuests(Instant now) {
        return UserMapper.toDomainList(jpaRepository.findExpiredGuests(now));
    }

    /**
     * Applies profile-level changes from domain model back to JPA entity.
     * Only updates fields that have @Setter on the JPA entity:
     * email, firstName, lastName, idNumber, phoneNumber, address, status,
     * expiresAt, isBiometricEnrolled, enrolledAt.
     *
     * For security-sensitive fields (password, lock status, login tracking, 2FA),
     * use the JPA entity's business methods directly.
     */
    private void applyProfileChanges(com.fivucsas.identity.entity.User jpa, User domain) {
        jpa.setEmail(domain.getEmail());
        jpa.setFirstName(domain.getFirstName());
        jpa.setLastName(domain.getLastName());
        jpa.setIdNumber(domain.getIdNumber());
        jpa.setPhoneNumber(domain.getPhoneNumber());
        jpa.setAddress(domain.getAddress());

        if (domain.getStatus() != null) {
            jpa.setStatus(com.fivucsas.identity.entity.UserStatus.valueOf(domain.getStatus().name()));
        }

        jpa.setExpiresAt(domain.getExpiresAt());
        jpa.setBiometricEnrolled(domain.isBiometricEnrolled());
        jpa.setEnrolledAt(domain.getEnrolledAt());
    }
}
