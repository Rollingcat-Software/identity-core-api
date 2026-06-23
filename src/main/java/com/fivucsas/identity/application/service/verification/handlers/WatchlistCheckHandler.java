package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Handles WATCHLIST_CHECK verification step.
 *
 * <p><b>STUB IMPLEMENTATION — gated to dev profile only.</b> Real KYC/AML provider
 * (Refinitiv / Dow Jones / Sayari / OpenSanctions / etc.) integration is Phase 4 scope.
 * Loading this bean under {@code prod} = bug — the {@code @Profile("dev")} annotation
 * below is the production safety ratchet. If you are looking at this class because
 * something exploded at boot under {@code prod}, the answer is NOT to remove the
 * annotation; the answer is to ship a real impl.
 *
 * <p>This is a mock that always returns {@code cleared=true,
 * match_count=0}. There is no real sanctions/watchlist provider wired (Refinitiv, Dow Jones,
 * Sayari, OpenSanctions, etc. — none are integrated). Returning a hard-coded "cleared"
 * verdict in production would silently false-pass any KYC/AML pipeline that includes a
 * {@code WATCHLIST_CHECK} step — a regulatory and security defect.
 *
 * <p>To make the silent-mock-in-prod failure mode impossible, this bean is gated to the
 * {@code dev} Spring profile only. In any non-dev profile (notably {@code prod}) the bean
 * is NOT registered, and {@code VerificationStepHandlerRegistry.getHandler("WATCHLIST_CHECK")}
 * will throw {@link UnsupportedOperationException} — surfacing an explicit "feature not
 * implemented" error rather than a counterfeit pass.
 *
 * <p>P0 fix: see {@code INVESTIGATION_MASTER_2026-05-07.md} P0-#3.
 *
 * <p>TODO: Integrate with real sanctions/watchlist APIs (OFAC, EU sanctions list, UN Security
 *          Council, PEP database). Replace this stub with a profile-agnostic component once a
 *          provider is contracted. Add configurable provider per tenant + fuzzy name matching
 *          with transliteration support.
 */
@Component
@Profile("dev")
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

        // TODO(#273): Replace with real sanctions API call
        log.info("Watchlist check (mock) for session {}: name={}, nationality={}, dob={}",
                session.getId(), name, nationality, dateOfBirth);

        return VerificationStepResult.success(1.0, Map.of(
                "cleared", true,
                "checked_lists", CHECKED_LISTS,
                "match_count", 0
        ));
    }
}
