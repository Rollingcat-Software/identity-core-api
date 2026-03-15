package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class UserEnrollmentRepositoryAdapter implements UserEnrollmentRepositoryPort {

    private final UserEnrollmentRepository jpaRepository;

    @Override
    public List<UserEnrollment> findAll() {
        return jpaRepository.findAll();
    }

    @Override
    public List<UserEnrollment> findAllByUserId(UUID userId) {
        return jpaRepository.findAllByUserId(userId);
    }

    @Override
    public Optional<UserEnrollment> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public Optional<UserEnrollment> findByUserIdAndAuthMethodType(UUID userId, AuthMethodType methodType) {
        return jpaRepository.findByUserIdAndAuthMethodType(userId, methodType);
    }

    @Override
    public boolean existsById(UUID id) {
        return jpaRepository.existsById(id);
    }

    @Override
    public void deleteById(UUID id) {
        jpaRepository.deleteById(id);
    }

    @Override
    public UserEnrollment save(UserEnrollment enrollment) {
        return jpaRepository.save(enrollment);
    }
}
