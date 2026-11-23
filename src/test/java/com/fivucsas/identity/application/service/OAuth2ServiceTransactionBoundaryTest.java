package com.fivucsas.identity.application.service;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionAttribute;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code authorization_code} exchange mints and saves a refresh token. When the
 * exchange ran inside the class-level {@code @Transactional(readOnly = true)}, the
 * joined read-only transaction never flushed, so the refresh token row was never
 * written and the client's first {@code refresh_token} grant always failed with
 * "Refresh token not found or has been revoked" (production, 2026-11-03 and
 * 2026-11-09, client fivucsas-mobile).
 *
 * <p>This asserts the transaction attribute Spring actually resolves for every
 * public {@code exchangeCode} overload, which is what decides read-only.
 */
class OAuth2ServiceTransactionBoundaryTest {

    private final AnnotationTransactionAttributeSource source = new AnnotationTransactionAttributeSource();

    @Test
    void exchangeCode_WhenTransactionAttributeIsResolved_ShouldBeAWriteTransaction() {
        List<Method> overloads = Arrays.stream(OAuth2Service.class.getDeclaredMethods())
                .filter(m -> m.getName().equals("exchangeCode"))
                .filter(m -> Modifier.isPublic(m.getModifiers()))
                .toList();

        assertThat(overloads).isNotEmpty();
        for (Method overload : overloads) {
            TransactionAttribute attribute = source.getTransactionAttribute(overload, OAuth2Service.class);
            assertThat(attribute)
                    .as("transaction attribute of %s", overload)
                    .isNotNull();
            assertThat(attribute.isReadOnly())
                    .as("%s mints a refresh token and must not run read-only", overload)
                    .isFalse();
        }
    }

    @Test
    void refreshAccessToken_WhenTransactionAttributeIsResolved_ShouldBeAWriteTransaction() {
        Method refresh = Arrays.stream(OAuth2Service.class.getDeclaredMethods())
                .filter(m -> m.getName().equals("refreshAccessToken"))
                .findFirst()
                .orElseThrow();

        TransactionAttribute attribute = source.getTransactionAttribute(refresh, OAuth2Service.class);

        assertThat(attribute).isNotNull();
        assertThat(attribute.isReadOnly()).isFalse();
    }
}
