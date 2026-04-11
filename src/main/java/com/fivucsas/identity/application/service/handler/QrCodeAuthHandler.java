package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class QrCodeAuthHandler implements AuthMethodHandler {

    private final QrCodeService qrCodeService;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.QR_CODE;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String qrToken = (String) data.get("qrToken");
        if (qrToken == null || qrToken.isEmpty()) {
            qrToken = (String) data.get("token");
        }

        if (qrToken == null || qrToken.isEmpty()) {
            return StepResult.failure("QR token is required");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before QR verification");
        }

        boolean valid = qrCodeService.validateToken(qrToken, session.getUser().getId());
        if (!valid) {
            log.warn("QR code validation failed for session: {}", session.getId());
            return StepResult.failure("Invalid or expired QR token");
        }

        log.info("QR code authentication successful for session: {}", session.getId());
        return StepResult.success();
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("qrToken");
    }
}
