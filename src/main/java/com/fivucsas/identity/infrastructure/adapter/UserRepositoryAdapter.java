package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter bridging the domain UserRepository port
 * to the Spring Data JPA repository.
 *
 * Follows Hexagonal Architecture: domain defines the port,
 * infrastructure provides the implementation.
 */
@Repository
@RequiredArgsConstructor
public class UserRepositoryAdapter implements com.fivucsas.identity.domain.repository.UserRepository {

    private final com.fivucsas.identity.repository.UserRepository jpaRepository;

    @Override
    public Optional<User> findByEmail(String email) {
        return jpaRepository.findByEmail(email);
    }

    @Override
    public boolean existsByEmail(String email) {
        return jpaRepository.existsByEmail(email);
    }

    @Override
    public List<User> findByStatus(UserStatus status) {
        return jpaRepository.findByStatus(status);
    }

    @Override
    public long countByStatus(UserStatus status) {
        return jpaRepository.countByStatus(status);
    }

    @Override
    public long countByIsBiometricEnrolled(boolean enrolled) {
        return jpaRepository.countByIsBiometricEnrolled(enrolled);
    }

    @Override
    public List<User> searchUsers(String query) {
        return jpaRepository.searchUsers(query);
    }

    @Override
    public Long sumVerificationCount() {
        return jpaRepository.sumVerificationCount();
    }

    @Override
    public <S extends User> S save(S user) {
        return jpaRepository.save(user);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public List<User> findAll() {
        return jpaRepository.findAll();
    }

    @Override
    public long count() {
        return jpaRepository.count();
    }

    @Override
    public void delete(User user) {
        jpaRepository.delete(user);
    }

    @Override
    public Optional<User> findByPasswordResetToken(String token) {
        return jpaRepository.findByPasswordResetToken(token);
    }

    @Override
    public Optional<User> findByEmailVerificationToken(String token) {
        return jpaRepository.findByEmailVerificationToken(token);
    }
}
