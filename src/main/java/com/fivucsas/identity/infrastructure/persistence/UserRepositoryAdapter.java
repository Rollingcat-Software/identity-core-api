package com.fivucsas.identity.infrastructure.persistence;

import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Adapter that bridges the domain UserRepository interface
 * to the Spring Data JPA UserRepository.
 *
 * This avoids having the JPA interface extend the domain interface directly,
 * which would cause ambiguous method resolution between CrudRepository
 * and the domain interface (e.g. findById, save).
 */
@Component
public class UserRepositoryAdapter implements UserRepository {

    private final com.fivucsas.identity.repository.UserRepository jpaUserRepository;

    public UserRepositoryAdapter(com.fivucsas.identity.repository.UserRepository jpaUserRepository) {
        this.jpaUserRepository = jpaUserRepository;
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return jpaUserRepository.findByEmail(email);
    }

    @Override
    public boolean existsByEmail(String email) {
        return jpaUserRepository.existsByEmail(email);
    }

    @Override
    public List<User> findByStatus(UserStatus status) {
        return jpaUserRepository.findByStatus(status);
    }

    @Override
    public long countByStatus(UserStatus status) {
        return jpaUserRepository.countByStatus(status);
    }

    @Override
    public long countByIsBiometricEnrolled(boolean enrolled) {
        return jpaUserRepository.countByIsBiometricEnrolled(enrolled);
    }

    @Override
    public List<User> searchUsers(String query) {
        return jpaUserRepository.searchUsers(query);
    }

    @Override
    public Long sumVerificationCount() {
        return jpaUserRepository.sumVerificationCount();
    }

    @Override
    public <S extends User> S save(S user) {
        return jpaUserRepository.save(user);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jpaUserRepository.findById(id);
    }

    @Override
    public List<User> findAll() {
        return jpaUserRepository.findAll();
    }

    @Override
    public long count() {
        return jpaUserRepository.count();
    }

    @Override
    public void delete(User user) {
        jpaUserRepository.delete(user);
    }

    @Override
    public Optional<User> findByPasswordResetToken(String token) {
        return jpaUserRepository.findByPasswordResetToken(token);
    }

    @Override
    public Optional<User> findByEmailVerificationToken(String token) {
        return jpaUserRepository.findByEmailVerificationToken(token);
    }

    @Override
    public List<User> findExpiredGuests(Instant cutoff) {
        return jpaUserRepository.findExpiredGuests(cutoff);
    }
}
