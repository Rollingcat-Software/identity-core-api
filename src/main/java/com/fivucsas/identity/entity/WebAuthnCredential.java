package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "webauthn_credentials",
       uniqueConstraints = @UniqueConstraint(columnNames = "credential_id"))
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class WebAuthnCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "credential_id", nullable = false, length = 512)
    private String credentialId;

    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "public_key_algorithm", nullable = false, length = 20)
    @Builder.Default
    private String publicKeyAlgorithm = "ES256";

    @Column(name = "sign_count", nullable = false)
    @Builder.Default
    private long signCount = 0;

    /**
     * Whether this credential was created as a discoverable (resident-key)
     * passkey. Discoverable passkeys can satisfy a usernameless assertion —
     * the authenticator returns the {@link #userHandle} so the RP resolves the
     * user without an up-front email. Non-discoverable credentials (the legacy
     * default, requireResidentKey=false) can only be used in an
     * {@code allowCredentials}-scoped assertion. Phase 1, V72.
     */
    @Column(name = "discoverable", nullable = false)
    @Builder.Default
    private boolean discoverable = false;

    /**
     * The WebAuthn user handle (PublicKeyCredentialUserEntity.id) bound to this
     * credential at registration time, stored base64url-encoded. For a
     * discoverable passkey the authenticator echoes this value on assertion;
     * the RP resolves the owning user from it (no email needed). We encode the
     * owning {@link User#getId()} UUID bytes — see {@code WebAuthnUserHandle}.
     * Phase 1, V72.
     */
    @Column(name = "user_handle", length = 255)
    private String userHandle;

    @Column(name = "device_name", length = 100)
    private String deviceName;

    @Column(name = "attestation_format", length = 50)
    private String attestationFormat;

    @Column(name = "transports", length = 255)
    private String transports;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    public void updateSignCount(long newSignCount) {
        this.signCount = newSignCount;
        this.lastUsedAt = Instant.now();
    }

    public void updateDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
}
