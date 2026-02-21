package com.fivucsas.identity.application.service.handler;

import java.util.Map;

public record StepResult(
    boolean succeeded,
    String error,
    Map<String, Object> data
) {
    public static StepResult success() {
        return new StepResult(true, null, Map.of());
    }

    public static StepResult success(Map<String, Object> data) {
        return new StepResult(true, null, data);
    }

    public static StepResult failure(String error) {
        return new StepResult(false, error, Map.of());
    }

    public boolean isSuccess() {
        return succeeded;
    }

    public String toJson() {
        if (succeeded) {
            return "{\"success\":true}";
        }
        return "{\"success\":false,\"error\":\"" + (error != null ? error.replace("\"", "\\\"") : "") + "\"}";
    }
}
