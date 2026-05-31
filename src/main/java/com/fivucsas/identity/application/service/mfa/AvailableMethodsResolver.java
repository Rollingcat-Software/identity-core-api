package com.fivucsas.identity.application.service.mfa;

import com.fivucsas.identity.dto.AvailableMfaMethod;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Builds the display list of auth methods offered at a single flow step, with ONE
 * generic "enrolled" rule shared by EVERY login layer.
 *
 * <p>Previously three call sites built this list independently and drifted apart —
 * the first layer used a PASSWORD-by-password-hash rule, while the later-layer and
 * switch-method builders fell back to enrollment-health (which has no row for
 * PASSWORD, since a password is set at user creation, not via the enrollment flow),
 * so the picker wrongly showed "PASSWORD not enrolled" from layer 2 onward.
 * Centralising the rule here removes that class of divergence.
 *
 * <p>The list is the step's FULL configured CHOICE set and is NEVER filtered by
 * already-completed methods: the client marks "already used" from the response's
 * authoritative {@code completedMethods}. The server-side {@code METHOD_ALREADY_USED}
 * substitution guard (in {@code VerifyMfaStepService}) remains the actual enforcement.
 */
@Component
public class AvailableMethodsResolver {

    /**
     * @param step        the flow step whose configured methods to list
     * @param hasPassword whether the user has a (non-blank) password hash — PASSWORD
     *                    is "enrolled" iff this is true (see {@link #hasPassword})
     * @param health      per-method enrollment health for the user (from
     *                    {@code EnrollmentHealthService.validateEnrollments})
     * @param preferred   the user's preferred 2FA method name (for the star marker)
     */
    public List<AvailableMfaMethod> build(AuthFlowStep step, boolean hasPassword,
                                          Map<AuthMethodType, Boolean> health, String preferred) {
        return step.getAvailableMethods().stream()
                .filter(Objects::nonNull)
                .map(m -> AvailableMfaMethod.builder()
                        .methodType(m.getType().name())
                        .name(m.getName())
                        .category(m.getCategory().name())
                        .enrolled(m.getType() == AuthMethodType.PASSWORD
                                ? hasPassword
                                : Boolean.TRUE.equals(health.get(m.getType())) || !m.isRequiresEnrollment())
                        .preferred(m.getType().name().equals(preferred))
                        .requiresEnrollment(m.isRequiresEnrollment())
                        .build())
                .collect(Collectors.toList());
    }

    /** PASSWORD is "enrolled" iff a non-blank password hash is set on the user. */
    public static boolean hasPassword(String passwordHash) {
        return passwordHash != null && !passwordHash.isBlank();
    }
}
