package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.repository.AuthFlowStepRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class AuthFlowStepRepositoryAdapter implements AuthFlowStepRepositoryPort {

    private final AuthFlowStepRepository jpaRepository;

    @Override
    public List<AuthFlowStep> findAllByAuthFlowIdOrderByStepOrderAsc(UUID flowId) {
        return jpaRepository.findAllByAuthFlowIdOrderByStepOrderAsc(flowId);
    }

    @Override
    public Optional<AuthFlowStep> findByAuthFlowIdAndId(UUID flowId, UUID stepId) {
        return jpaRepository.findByAuthFlowIdAndId(flowId, stepId);
    }

    @Override
    public void deleteAllByAuthFlowId(UUID flowId) {
        jpaRepository.deleteAllByAuthFlowId(flowId);
    }

    @Override
    public AuthFlowStep save(AuthFlowStep step) {
        return jpaRepository.save(step);
    }
}
