package com.fivucsas.identity.application.service.authorTrial;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuthorTrialAccessGuard — flag + key + single tenant")
class AuthorTrialAccessGuardTest {

    private static final UUID TENANT = UUID.fromString("aaaaaaaa-1111-2222-3333-444444444444");
    private static final UUID OTHER = UUID.fromString("bbbbbbbb-1111-2222-3333-444444444444");

    private AuthorTrialProperties properties(boolean enabled, String code, List<String> tenants) {
        AuthorTrialProperties properties = new AuthorTrialProperties();
        properties.setEnabled(enabled);
        properties.setAccessCode(code);
        properties.setTenantIds(tenants);
        return properties;
    }

    @Test
    void surfaceIsEnabledOnlyWhenFullyConfigured() {
        assertThat(new AuthorTrialAccessGuard(properties(false, "code", List.of(TENANT.toString())))
                .surfaceEnabled()).isFalse();
        assertThat(new AuthorTrialAccessGuard(properties(true, "", List.of(TENANT.toString())))
                .surfaceEnabled()).isFalse();
        assertThat(new AuthorTrialAccessGuard(properties(true, "  ", List.of(TENANT.toString())))
                .surfaceEnabled()).isFalse();
        assertThat(new AuthorTrialAccessGuard(properties(true, "code", List.of()))
                .surfaceEnabled()).isFalse();
        assertThat(new AuthorTrialAccessGuard(properties(true, "code", List.of(TENANT.toString(), OTHER.toString())))
                .surfaceEnabled()).isFalse();
        assertThat(new AuthorTrialAccessGuard(properties(true, "code", List.of(TENANT.toString())))
                .surfaceEnabled()).isTrue();
    }

    @Test
    void keyIsComparedExactlyAndOnlyWhenEnabled() {
        AuthorTrialAccessGuard guard = new AuthorTrialAccessGuard(
                properties(true, "shared-secret", List.of(TENANT.toString())));

        assertThat(guard.keyMatches("shared-secret")).isTrue();
        assertThat(guard.keyMatches("shared-secret ")).isFalse();
        assertThat(guard.keyMatches("SHARED-SECRET")).isFalse();
        assertThat(guard.keyMatches(null)).isFalse();

        AuthorTrialAccessGuard disabled = new AuthorTrialAccessGuard(
                properties(false, "shared-secret", List.of(TENANT.toString())));
        assertThat(disabled.keyMatches("shared-secret")).isFalse();
    }

    @Test
    void malformedTenantEntriesAreIgnored() {
        AuthorTrialProperties properties = properties(true, "code",
                List.of("not-a-uuid", TENANT.toString()));
        AuthorTrialAccessGuard guard = new AuthorTrialAccessGuard(properties);

        assertThat(guard.surfaceEnabled()).isTrue();
        assertThat(guard.trialTenantId()).contains(TENANT);
    }
}