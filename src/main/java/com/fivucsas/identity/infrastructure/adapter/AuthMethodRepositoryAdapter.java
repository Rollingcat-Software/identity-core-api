package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.repository.AuthMethodRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class AuthMethodRepositoryAdapter implements AuthMethodRepositoryPort {

    private final AuthMethodRepository jpaRepository;

    @Override
    public List<AuthMethod> findAllByIsActiveTrue() {
        return jpaRepository.findAllByIsActiveTrue();
    }

    @Override
    public Optional<AuthMethod> findByType(AuthMethodType type) {
        return jpaRepository.findByType(type);
    }

    @Override
    public Optional<AuthMethod> findById(UUID id) {
        return jpaRepository.findById(id);
    }
}
