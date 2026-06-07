package com.fivucsas.identity.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Turkish-locale casing pitfall on the SECURITY paths (authz fix, 2026-06-07).
 *
 * <p>Java's {@code toUpperCase()/toLowerCase()} without an explicit {@link Locale}
 * use the JVM default locale. Under {@code tr-TR} the dotted/dotless-I mapping
 * means {@code "i".toUpperCase()} → {@code "İ"} and {@code "I".toLowerCase()} →
 * {@code "ı"} — so a permission/authority string built with bare casing on a
 * Turkish JVM no longer matches the seeded ASCII authority (a silent authz
 * bypass/denial). These tests force the default locale to Turkish and assert the
 * security identifiers stay pure-ASCII because the production code now uses
 * {@link Locale#ROOT}.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("Turkish-locale casing on security paths must use Locale.ROOT")
class TurkishLocalePermissionCasingTest {

    private static final Locale TURKISH = new Locale("tr", "TR");
    private Locale originalDefault;

    @BeforeEach
    void forceTurkishLocale() {
        originalDefault = Locale.getDefault();
        Locale.setDefault(TURKISH);
    }

    @AfterEach
    void restoreLocale() {
        Locale.setDefault(originalDefault);
    }

    @Test
    @DisplayName("entity.Permission.of/getAuthorityName → 'identity:read' stays ASCII under tr-TR")
    void entityPermission_WhenTurkishLocale_ShouldProduceAsciiAuthority() {
        // 'identity'/'read' both contain 'i' — the exact char the Turkish locale
        // would mangle (i→İ on upper, I→ı on lower) without Locale.ROOT.
        com.fivucsas.identity.entity.Permission perm =
                com.fivucsas.identity.entity.Permission.of("identity", "read", "desc");

        assertThat(perm.getName()).isEqualTo("IDENTITY:READ");
        assertThat(perm.getAuthorityName()).isEqualTo("identity:read");
        // Explicitly assert no Turkish dotted/dotless I leaked in.
        assertThat(perm.getAuthorityName()).doesNotContain("İ").doesNotContain("ı");
    }

    @Test
    @DisplayName("domain.Permission.create/getAuthorityName → 'identity:write' stays ASCII under tr-TR")
    void domainPermission_WhenTurkishLocale_ShouldProduceAsciiAuthority() {
        com.fivucsas.identity.domain.model.permission.Permission perm =
                com.fivucsas.identity.domain.model.permission.Permission.create(
                        "identity", "write", "desc");

        assertThat(perm.getName()).isEqualTo("IDENTITY:WRITE");
        assertThat(perm.getAuthorityName()).isEqualTo("identity:write");
        assertThat(perm.getAuthorityName()).doesNotContain("İ").doesNotContain("ı");
    }

    @Test
    @DisplayName("RbacPermissionEvaluator.hasPermission(type,perm) → builds 'device:read' (not 'DEVİCE:read') under tr-TR")
    void permissionEvaluator_WhenTurkishLocale_ShouldBuildAsciiPermissionString() {
        RbacAuthorizationService rbac = mock(RbacAuthorizationService.class);
        // Capture exactly the permission string the evaluator forwards.
        when(rbac.hasPermission(eq("device:read"))).thenReturn(true);
        // Any Turkish-mangled variant must NOT match → would return false.
        RbacPermissionEvaluator evaluator = new RbacPermissionEvaluator(rbac);

        Authentication auth =
                new UsernamePasswordAuthenticationToken("admin@example.com", "x");

        // targetType "Device" + permission "READ": bare casing under tr-TR would
        // yield "devİce:read" (i→İ is independent of upper/lower, but the
        // lowercase of "Device" via the Turkish locale keeps the dotted-i; the
        // real regression is "DEVICE".toLowerCase(tr) → "devıce"). We pass the
        // form that would mangle and assert the ASCII match still works.
        boolean granted = evaluator.hasPermission(auth, null, "DEVICE", "READ");

        assertThat(granted)
                .as("evaluator must forward the ASCII 'device:read', matching the seeded authority")
                .isTrue();
    }
}
