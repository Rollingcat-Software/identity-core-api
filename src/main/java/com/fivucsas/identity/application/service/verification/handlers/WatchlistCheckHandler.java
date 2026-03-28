package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Handles WATCHLIST_CHECK verification step.
 * Mock implementation that always clears the check.
 *
 * TODO: Integrate with real sanctions/watchlist APIs (OFAC, EU sanctions list, UN Security Council)
 * TODO: Add configurable watchlist providers per tenant
 * TODO: Implement fuzzy name matching with transliteration support
 */
@Component
@Slf4j
public class WatchlistCheckHandler implements VerificationStepHandler {

    private static final List<String> CHECKED_LISTS = List.of("OFAC", "EU", "UN");

    @Override
    public String getStepType() {
        return "WATCHLIST_CHECK";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String name = (String) data.get("name");
        String nationality = (String) data.get("nationality");
        String dateOfBirth = (String) data.get("date_of_birth");

        if (name == null || name.isBlank()) {
            return VerificationStepResult.failure("Name is required for watchlist check");
        }

        // TODO: Replace with real sanctions API call
        log.info("Watchlist check (mock) for session {}: name={}, nationality={}, dob={}",
                session.getId(), name, nationality, dateOfBirth);

        return VerificationStepResult.success(1.0, Map.of(
                "cleared", true,
                "checked_lists", CHECKED_LISTS,
                "match_count", 0
        ));
    }
}
