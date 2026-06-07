package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "user_settings")
// Defense-in-depth tenant isolation (authz cross-tenant IDOR fix, 2026-06-07).
// @FilterDef is global from User.java; tenant_id added by Flyway V84. The
// application-layer guard (UserController.assertCanAccessUserSettings) is the
// primary control — this @Filter is a backstop that scopes settings reads to the
// active tenant when the filter is enabled, matching AuditLog/UserEnrollment/etc.
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSettings {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;

    /**
     * Owning tenant — mirrors {@code users.tenant_id} of {@link #userId}. Backs the
     * {@code @Filter(tenantFilter)} above (Flyway V84). Nullable at the column level
     * (the migration is metadata-only); write paths populate it from the owning
     * user's tenant so the filter is effective for rows created after V84.
     */
    @Column(name = "tenant_id")
    private UUID tenantId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", nullable = false)
    @Builder.Default
    private Map<String, Object> settings = Map.of();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
