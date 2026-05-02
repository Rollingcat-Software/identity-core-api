package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.AuthSessionResponse;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.AuthSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Admin-level cross-tenant read aggregator.
 *
 * <p>Holds the read-side transaction boundary for {@code AdminOverviewController}'s
 * list endpoints so the controller stays free of {@code @Transactional}. Lazy
 * associations on {@link com.fivucsas.identity.entity.AuthFlow} and
 * {@link com.fivucsas.identity.entity.AuthSession} are dereferenced inside the
 * mapping step below, so the transaction boundary must surround that work
 * rather than the HTTP serialization (where OSIV is OFF in prod and lazy
 * loads silently fail).</p>
 *
 * <p>Quality batch P1-Q9 (review 2026-05-01): moved here from
 * {@code AdminOverviewController} per the "no @Transactional on controllers"
 * rule.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class AdminOverviewService {

    private final AuthFlowRepository authFlowRepository;
    private final AuthSessionRepository authSessionRepository;

    public List<AuthFlowResponse> listAllAuthFlows(OperationType operationType) {
        return authFlowRepository.findAll().stream()
                .filter(f -> operationType == null || f.getOperationType() == operationType)
                .map(AuthFlowResponse::from)
                .toList();
    }

    public List<AuthSessionResponse> listAllAuthSessions() {
        return authSessionRepository.findAll().stream()
                .map(AuthSessionResponse::from)
                .toList();
    }
}
