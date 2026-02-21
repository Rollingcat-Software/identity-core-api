package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.AuthMethodResponse;
import com.fivucsas.identity.application.port.input.ManageAuthMethodUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/auth-methods")
@RequiredArgsConstructor
public class AuthMethodController {

    private final ManageAuthMethodUseCase manageAuthMethodUseCase;

    @GetMapping
    public ResponseEntity<List<AuthMethodResponse>> getAllMethods() {
        return ResponseEntity.ok(manageAuthMethodUseCase.listAllMethods());
    }

    @GetMapping("/{type}")
    public ResponseEntity<AuthMethodResponse> getMethodByType(@PathVariable AuthMethodType type) {
        return ResponseEntity.ok(manageAuthMethodUseCase.getMethodByType(type));
    }
}
