package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.service.handler.AuthMethodHandler;
import com.fivucsas.identity.application.service.handler.StepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthMethodHandlerRegistry {

    private final List<AuthMethodHandler> handlers;
    private final Map<AuthMethodType, AuthMethodHandler> handlerMap = new HashMap<>();

    @PostConstruct
    public void init() {
        for (AuthMethodHandler handler : handlers) {
            handlerMap.put(handler.getMethodType(), handler);
            log.info("Registered auth handler: {}", handler.getMethodType());
        }
    }

    public AuthMethodHandler getHandler(AuthMethodType type) {
        AuthMethodHandler handler = handlerMap.get(type);
        if (handler == null) {
            throw new UnsupportedOperationException("No handler registered for method type: " + type);
        }
        return handler;
    }

    public boolean hasHandler(AuthMethodType type) {
        return handlerMap.containsKey(type);
    }
}
