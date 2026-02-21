package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthFlowStep;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthFlowStepRepository extends JpaRepository<AuthFlowStep, UUID> {
    List<AuthFlowStep> findAllByAuthFlowIdOrderByStepOrderAsc(UUID flowId);
    Optional<AuthFlowStep> findByAuthFlowIdAndId(UUID flowId, UUID stepId);
    void deleteAllByAuthFlowId(UUID flowId);
}
