package com.fivucsas.identity.application.service.verification;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Registry that collects all VerificationStepHandler beans via Spring DI
 * and provides lookup by step type.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationStepHandlerRegistry {

    private final List<VerificationStepHandler> handlers;
    private final Map<String, VerificationStepHandler> handlerMap = new HashMap<>();

    @PostConstruct
    public void init() {
        for (VerificationStepHandler handler : handlers) {
            handlerMap.put(handler.getStepType(), handler);
            log.info("Registered verification step handler: {}", handler.getStepType());
        }
        log.info("Total verification step handlers registered: {}", handlerMap.size());
    }

    public VerificationStepHandler getHandler(String stepType) {
        VerificationStepHandler handler = handlerMap.get(stepType);
        if (handler == null) {
            throw new UnsupportedOperationException("No verification handler registered for step type: " + stepType);
        }
        return handler;
    }

    public boolean hasHandler(String stepType) {
        return handlerMap.containsKey(stepType);
    }
}
