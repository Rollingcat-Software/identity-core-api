package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthBiometricChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthBiometricChallengeRepository extends JpaRepository<AuthBiometricChallenge, UUID> {
    Optional<AuthBiometricChallenge> findByChallengeId(UUID challengeId);
}
