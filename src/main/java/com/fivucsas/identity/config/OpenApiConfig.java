package com.fivucsas.identity.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI / Swagger configuration.
 *
 * Generates an exportable OpenAPI 3.0 spec at /api-docs
 * and provides the Swagger UI at /swagger-ui.html.
 */
@Configuration
public class OpenApiConfig {

    @Value("${server.port:8080}")
    private int serverPort;

    @Bean
    public OpenAPI identityCoreOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("FIVUCSAS Identity Core API")
                        .description("Multi-tenant identity management API with multi-factor authentication, "
                                + "biometric enrollment, RBAC, and guest lifecycle management.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Rolling Cat Software")
                                .url("https://fivucsas.com"))
                        .license(new License()
                                .name("Proprietary")))
                .servers(List.of(
                        new Server().url("http://localhost:" + serverPort).description("Local development"),
                        new Server().url("https://app.fivucsas.com").description("Production")))
                .components(new Components()
                        .addSecuritySchemes("bearer-jwt", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT access token obtained from /api/v1/auth/login")));
    }
}
