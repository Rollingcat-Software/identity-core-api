package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.LoginConfigResponse;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Builds the public {@link LoginConfigResponse} for a tenant's default
 * APP_LOGIN flow (task #16 C). Unauthenticated — exposes only what a login
 * surface needs and NO internal IDs.
 *
 * <p>When the tenant has no default APP_LOGIN flow we return an implicit
 * single-step PASSWORD config (matching the legacy default-login behavior of
 * {@link AuthenticateUserService}), so a freshly-provisioned tenant still
 * renders a usable password login.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class LoginConfigService {

    private final AuthFlowRepositoryPort authFlowRepository;
    private final TenantRepository tenantRepository;
    private final OAuth2ClientRepositoryPort oAuth2ClientRepository;
    private final ConfigDrivenLoginPolicy configDrivenLoginPolicy;

    /**
     * Resolve the login config for the tenant that OWNS a given identifier, for
     * the cross-tenant dashboard's identifier-first step. The dashboard
     * (app.fivucsas.com) carries no tenantId/clientId, so until the user types
     * their email it can only show the platform default — this lets the email
     * step resolve the caller's ACTUAL tenant flow (Layer-1 methods + step
     * count) so the password screen shows "1/3" and the flexible flow the
     * tenant configured, instead of the hardcoded platform PASSWORD-first
     * totalSteps=1.
     *
     * <p>The email→tenant resolution happens upstream (in
     * {@code AuthenticateUserService}, which legitimately works with the user
     * entity); a {@code null} tenantId (unknown email) yields the platform
     * config so a non-existent email is indistinguishable from a single-step
     * password tenant. A real email reveals only the tenant's PUBLIC
     * login-config (already exposed by {@code GET /login-config?tenantId}); the
     * step count is surfaced one screen earlier than the password-step gate
     * already does.
     */
    @Transactional(readOnly = true)
    public LoginConfigResponse getLoginConfigForTenantOrPlatform(UUID tenantId) {
        return tenantId != null ? getLoginConfig(tenantId) : getPlatformLoginConfig();
    }

    /**
     * Resolve a tenant's login config from an OAuth2 {@code client_id} instead of
     * a raw tenant UUID. The hosted login surface (verify.fivucsas.com) only
     * carries the OIDC {@code client_id} in its {@code /authorize} request, never
     * the internal tenant id, so it calls this variant. Returns empty when the
     * client is unknown or not bound to a tenant (the controller maps that to 404).
     */
    @Transactional(readOnly = true)
    public Optional<LoginConfigResponse> getLoginConfigByClientId(String clientId) {
        return oAuth2ClientRepository.findByClientId(clientId)
                .map(client -> client.getTenant())
                .filter(Objects::nonNull)
                .map(tenant -> getLoginConfig(tenant.getId()));
    }

    @Transactional(readOnly = true)
    public LoginConfigResponse getLoginConfig(UUID tenantId) {
        String tenantName = tenantRepository.findById(tenantId)
                .map(Tenant::getName)
                .orElse(null);

        // REVERSIBILITY GATE (operator directive 2026-05-30): when the engine is
        // OFF for this tenant, advertise the legacy password-first shape so the
        // login UI behaves EXACTLY as today (single PASSWORD Layer-1,
        // identifierRequired=true). The actual login path also stays legacy, so
        // the contract and the engine agree.
        if (!configDrivenLoginPolicy.isEnabledFor(tenantId)) {
            return passwordFirstConfig(tenantId, tenantName, false);
        }

        Optional<AuthFlow> defaultLoginFlow = authFlowRepository
                .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                        tenantId, OperationType.APP_LOGIN);

        if (defaultLoginFlow.isEmpty()) {
            // No configured flow → implicit single-step PASSWORD login. Engine is
            // still ON for this tenant (we passed the gate above).
            return passwordFirstConfig(tenantId, tenantName, true);
        }

        AuthFlow flow = defaultLoginFlow.get();
        List<AuthFlowStep> steps = flow.getSteps().stream()
                .sorted(Comparator.comparingInt(AuthFlowStep::getStepOrder))
                .toList();

        AuthFlowStep step1 = steps.stream()
                .filter(s -> s.getStepOrder() == 1)
                .findFirst()
                .orElse(null);

        List<LoginConfigResponse.Method> layer1Methods = step1 == null
                ? List.of(new LoginConfigResponse.Method("PASSWORD", false, true))
                : toMethods(step1);

        // The surface must collect an identifier up front UNLESS every Layer-1
        // method is usernameless (the user resolves from the factor alone).
        boolean identifierRequired = layer1Methods.isEmpty()
                || !layer1Methods.stream().allMatch(LoginConfigResponse.Method::usernameless);

        List<LoginConfigResponse.LaterStep> laterSteps = steps.stream()
                .filter(s -> s.getStepOrder() > 1)
                .map(s -> new LoginConfigResponse.LaterStep(s.getStepOrder(), toMethods(s)))
                .toList();

        return new LoginConfigResponse(
                tenantId.toString(), tenantName,
                new LoginConfigResponse.Layer1(layer1Methods, identifierRequired),
                flow.getStepCount(),
                laterSteps,
                true);
    }

    /**
     * The legacy single-step PASSWORD-first config. Returned when the engine is
     * OFF for the tenant OR the tenant has no default APP_LOGIN flow — in both
     * cases the actual login path is the legacy password login, so the contract
     * matches the runtime behavior.
     */
    /**
     * Platform (no-tenant) login config for the dashboard's OWN login surface,
     * which is cross-tenant (any tenant's user signs in there) and therefore has
     * no single tenant to consult. PASSWORD-first Layer-1; {@code engineActive}
     * follows the GLOBAL master switch only, so app.fivucsas opens identifier-first
     * exactly when the engine is globally enabled and reverts with the flag.
     */
    public LoginConfigResponse getPlatformLoginConfig() {
        // PASSWORD-first, PLUS a usernameless PASSKEY so the dashboard's own login
        // surface offers the passkey one-tap shortcut (parity with verify.fivucsas,
        // whose per-tenant configs declare PASSKEY). This config drives only what the
        // dashboard RENDERS at Layer-1 — discoverable-passkey auth is cross-tenant and
        // enforcement stays per the user's tenant flow, so adding it is an affordance,
        // not a policy change. Kept separate from passwordFirstConfig() (shared by the
        // tenant flag-OFF fallback) so this does NOT leak passkey onto every tenant.
        LoginConfigResponse.Method password =
                new LoginConfigResponse.Method("PASSWORD", false, true);
        LoginConfigResponse.Method passkey =
                new LoginConfigResponse.Method("PASSKEY", true, true);
        return new LoginConfigResponse(
                "00000000-0000-0000-0000-000000000000", "platform",
                new LoginConfigResponse.Layer1(List.of(password, passkey), true),
                1, List.of(), configDrivenLoginPolicy.isGloballyEnabled());
    }

    private LoginConfigResponse passwordFirstConfig(UUID tenantId, String tenantName, boolean engineActive) {
        LoginConfigResponse.Method password =
                new LoginConfigResponse.Method("PASSWORD", false, true);
        return new LoginConfigResponse(
                tenantId.toString(), tenantName,
                new LoginConfigResponse.Layer1(List.of(password), true),
                1, List.of(), engineActive);
    }

    private List<LoginConfigResponse.Method> toMethods(AuthFlowStep step) {
        return step.getAvailableMethods().stream()
                .filter(Objects::nonNull)
                .map(this::toMethod)
                .toList();
    }

    private LoginConfigResponse.Method toMethod(AuthMethod m) {
        return new LoginConfigResponse.Method(
                m.getType().name(),
                m.isSupportsUsernameless(),
                m.isRequiresEnrollment());
    }
}
