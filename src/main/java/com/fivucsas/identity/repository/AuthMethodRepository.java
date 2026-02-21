package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthMethodRepository extends JpaRepository<AuthMethod, UUID> {
    Optional<AuthMethod> findByType(AuthMethodType type);
    List<AuthMethod> findAllByIsActiveTrue();
}
