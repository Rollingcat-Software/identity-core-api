package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthSessionStep;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthSessionStepRepository extends JpaRepository<AuthSessionStep, UUID> {
    List<AuthSessionStep> findAllBySessionId(UUID sessionId);
    Optional<AuthSessionStep> findBySessionIdAndAuthFlowStepId(UUID sessionId, UUID flowStepId);
    Optional<AuthSessionStep> findByDelegationToken(String token);
}
