package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

@Entity
@Table(name = "auth_flow_steps")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AuthFlowStep {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "auth_flow_id", nullable = false)
    private AuthFlow authFlow;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "auth_method_id", nullable = false)
    private AuthMethod authMethod;

    @Column(name = "step_order", nullable = false)
    private int stepOrder;

    @Column(name = "is_required", nullable = false)
    @Builder.Default
    private boolean isRequired = true;

    @Column(name = "timeout_seconds", nullable = false)
    @Builder.Default
    private int timeoutSeconds = 120;

    @Column(name = "max_attempts", nullable = false)
    @Builder.Default
    private int maxAttempts = 3;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "fallback_method_id")
    private AuthMethod fallbackMethod;

    @Column(name = "allows_delegation", nullable = false)
    @Builder.Default
    private boolean allowsDelegation = true;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private String config = "{}";

    public void updateOrder(int newOrder) {
        this.stepOrder = newOrder;
    }

    public void updateSettings(boolean isRequired, int timeoutSeconds, int maxAttempts, boolean allowsDelegation) {
        this.isRequired = isRequired;
        this.timeoutSeconds = timeoutSeconds;
        this.maxAttempts = maxAttempts;
        this.allowsDelegation = allowsDelegation;
    }
}
