package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "user_devices")
// Defense-in-depth tenant isolation (P0-1). @FilterDef is global from User.java.
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class UserDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "device_name", length = 100)
    private String deviceName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private DevicePlatform platform;

    @Column(name = "device_fingerprint", nullable = false, length = 255)
    private String deviceFingerprint;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(columnDefinition = "text[]", nullable = false)
    @Builder.Default
    private List<String> capabilities = List.of();

    @Column(name = "push_token", columnDefinition = "TEXT")
    private String pushToken;

    @Column(name = "is_trusted", nullable = false)
    @Builder.Default
    private boolean isTrusted = false;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "registered_at", nullable = false)
    @Builder.Default
    private Instant registeredAt = Instant.now();

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "public_key_algorithm", length = 20)
    @Builder.Default
    private String publicKeyAlgorithm = "EC_P256";

    @Column(name = "step_up_registered_at")
    private Instant stepUpRegisteredAt;

    public void registerStepUpKey(String publicKey, String algorithm) {
        this.publicKey = publicKey;
        this.publicKeyAlgorithm = algorithm != null ? algorithm : "EC_P256";
        this.stepUpRegisteredAt = Instant.now();
    }

    public boolean isStepUpEnabled() {
        return this.publicKey != null;
    }

    public void trust() {
        this.isTrusted = true;
    }

    public void untrust() {
        this.isTrusted = false;
    }

    public void updateLastUsed() {
        this.lastUsedAt = Instant.now();
    }

    public void updatePushToken(String pushToken) {
        this.pushToken = pushToken;
    }

    public void updateName(String name) {
        this.deviceName = name;
    }
}
