package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "biometric_data")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BiometricData {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(columnDefinition = "vector(512)", nullable = false)
    private String embedding; // Stored as vector(512) in pgvector

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant enrolledAt;
}
