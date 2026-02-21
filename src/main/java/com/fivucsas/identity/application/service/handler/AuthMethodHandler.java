package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;

import java.util.Map;
import java.util.Set;

public interface AuthMethodHandler {
    AuthMethodType getMethodType();
    StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data);
    boolean requiresEnrollment();
    Set<String> requiredDataFields();
}
