package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "auth_methods")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AuthMethod {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(unique = true, nullable = false, length = 30)
    private AuthMethodType type;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthMethodCategory category;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "platforms", columnDefinition = "text[]", nullable = false)
    private List<String> platforms;

    @Column(name = "requires_enrollment", nullable = false)
    @Builder.Default
    private boolean requiresEnrollment = false;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "config_schema", columnDefinition = "jsonb")
    @Builder.Default
    private String configSchema = "{}";

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;
}
