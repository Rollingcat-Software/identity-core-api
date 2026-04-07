package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.StepType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.ArrayList;
import java.util.List;
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

    @Enumerated(EnumType.STRING)
    @Column(name = "step_type", nullable = false, length = 20)
    @Builder.Default
    private StepType stepType = StepType.SEQUENTIAL;

    /**
     * For CHOICE steps: the alternative auth methods the user can pick from.
     * For SEQUENTIAL steps: this list is empty (only authMethod is used).
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "auth_flow_step_methods",
        joinColumns = @JoinColumn(name = "step_id"),
        inverseJoinColumns = @JoinColumn(name = "auth_method_id")
    )
    @OrderColumn(name = "display_order")
    @Builder.Default
    private List<AuthMethod> alternativeMethods = new ArrayList<>();

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

    /**
     * Returns all auth methods available for this step.
     * For SEQUENTIAL: returns just the primary auth method.
     * For CHOICE: returns the alternative methods list.
     */
    public List<AuthMethod> getAvailableMethods() {
        if (stepType == StepType.CHOICE && alternativeMethods != null && !alternativeMethods.isEmpty()) {
            // Filter nulls: @OrderColumn gaps produce null entries
            return alternativeMethods.stream()
                .filter(java.util.Objects::nonNull)
                .toList();
        }
        return authMethod != null ? List.of(authMethod) : List.of();
    }

    public boolean isChoice() {
        return stepType == StepType.CHOICE;
    }
}
