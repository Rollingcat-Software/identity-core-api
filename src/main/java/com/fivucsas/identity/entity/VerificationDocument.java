package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(name = "verification_documents")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class VerificationDocument {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private VerificationSession session;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "document_type", nullable = false, length = 30)
    private String documentType;

    @Column(name = "document_number", length = 50)
    private String documentNumber;

    @Column(name = "holder_name", length = 200)
    private String holderName;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Column(name = "expiry_date")
    private LocalDate expiryDate;

    @Column(name = "nationality", length = 5)
    private String nationality;

    @Column(name = "mrz_data", columnDefinition = "TEXT")
    private String mrzData;

    @Column(name = "face_image_hash", length = 64)
    private String faceImageHash;

    @Column(name = "verified")
    @Builder.Default
    private boolean verified = false;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    public void markVerified() {
        this.verified = true;
    }
}
