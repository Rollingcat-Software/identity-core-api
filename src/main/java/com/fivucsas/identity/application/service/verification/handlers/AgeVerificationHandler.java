package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeParseException;
import java.util.Map;

/**
 * Handles AGE_VERIFICATION step.
 * Calculates age from date_of_birth and checks against a configurable minimum.
 */
@Component
@Slf4j
public class AgeVerificationHandler implements VerificationStepHandler {

    @Value("${verification.age.minimum:18}")
    private int defaultMinimumAge;

    @Override
    public String getStepType() {
        return "AGE_VERIFICATION";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String dobStr = (String) data.get("date_of_birth");
        if (dobStr == null || dobStr.isBlank()) {
            return VerificationStepResult.failure("Date of birth is required for age verification");
        }

        LocalDate dateOfBirth;
        try {
            dateOfBirth = LocalDate.parse(dobStr);
        } catch (DateTimeParseException e) {
            return VerificationStepResult.failure("Invalid date_of_birth format. Expected ISO-8601 (YYYY-MM-DD)");
        }

        // Allow per-step minimum age override, fall back to config default
        int minimumAge = defaultMinimumAge;
        Object minAgeOverride = data.get("minimum_age");
        if (minAgeOverride instanceof Number num) {
            minimumAge = num.intValue();
        } else if (minAgeOverride instanceof String s) {
            try { minimumAge = Integer.parseInt(s); } catch (NumberFormatException ignored) {}
        }

        int age = Period.between(dateOfBirth, LocalDate.now()).getYears();
        boolean meetsRequirement = age >= minimumAge;

        Map<String, Object> resultData = Map.of(
                "age", age,
                "minimum_required", minimumAge,
                "meets_requirement", meetsRequirement
        );

        if (meetsRequirement) {
            log.info("Age verification passed for session {}: age={}, minimum={}", session.getId(), age, minimumAge);
            return VerificationStepResult.success(1.0, resultData);
        } else {
            log.warn("Age verification failed for session {}: age={}, minimum={}", session.getId(), age, minimumAge);
            return VerificationStepResult.failure("Age requirement not met", resultData);
        }
    }
}
