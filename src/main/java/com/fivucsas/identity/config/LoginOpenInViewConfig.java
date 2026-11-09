package com.fivucsas.identity.config;

import jakarta.persistence.EntityManagerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.orm.jpa.support.OpenEntityManagerInViewInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Open-in-view for every request except the password login (identity-core-api #285).
 *
 * <p>With open-in-view the request-bound EntityManager keeps the first JDBC
 * connection it touches until the response is written. The login splits its work
 * into short transactions and runs audit writes and the biometric probe between
 * them; with a request-bound EntityManager it would still hold its first connection
 * during all of that and need a second one, which starved the Hikari pool at about
 * 20 concurrent logins. {@code spring.jpa.open-in-view} is therefore off, and this
 * class registers Spring's interceptor for all other paths.</p>
 *
 * <p>Why not turn open-in-view off everywhere: {@code TenantFilterAspect} and
 * {@code TenantHibernateAspect} unwrap the shared EntityManager before every
 * repository call to enable the tenant filter. Outside a transaction that only
 * works while open-in-view binds an EntityManager to the request, so repository
 * calls that run outside a transaction on other endpoints would break or lose
 * tenant scoping. The login path keeps every repository call inside a transaction.</p>
 */
@Configuration
public class LoginOpenInViewConfig implements WebMvcConfigurer {

    /** Endpoint served by {@code AuthController.login}; must match its mapping. */
    static final String PASSWORD_LOGIN_PATH = "/api/v1/auth/login";

    // An ObjectProvider so MVC test slices without JPA still start (they have no
    // EntityManagerFactory and need no open-in-view).
    private final ObjectProvider<EntityManagerFactory> entityManagerFactory;

    public LoginOpenInViewConfig(ObjectProvider<EntityManagerFactory> entityManagerFactory) {
        this.entityManagerFactory = entityManagerFactory;
    }

    @Override
    public void addInterceptors(@NonNull InterceptorRegistry registry) {
        EntityManagerFactory factory = entityManagerFactory.getIfUnique();
        if (factory == null) {
            return;
        }
        OpenEntityManagerInViewInterceptor openInView = new OpenEntityManagerInViewInterceptor();
        openInView.setEntityManagerFactory(factory);
        registry.addWebRequestInterceptor(openInView).excludePathPatterns(PASSWORD_LOGIN_PATH);
    }
}
