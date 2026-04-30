package com.fivucsas.identity.entity;

import com.fivucsas.identity.domain.model.auth.FlowType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "auth_flows")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AuthFlow {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * JPA-safe equality by immutable id (P2.10). See {@link User#equals(Object)}
     * for full rationale.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthFlow other)) return false;
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return AuthFlow.class.hashCode();
    }

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "flow_type", nullable = false, length = 30)
    @Builder.Default
    private FlowType flowType = FlowType.AUTHENTICATION;

    @Column(name = "industry_template", length = 50)
    private String industryTemplate;

    @Enumerated(EnumType.STRING)
    @Column(name = "operation_type", nullable = false, length = 30)
    private OperationType operationType;

    @Column(name = "is_default", nullable = false)
    @Builder.Default
    private boolean isDefault = false;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @OneToMany(mappedBy = "authFlow", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("stepOrder ASC")
    @Builder.Default
    private List<AuthFlowStep> steps = new ArrayList<>();

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    public void activate() {
        this.isActive = true;
    }

    public void deactivate() {
        this.isActive = false;
    }

    public void setAsDefault() {
        this.isDefault = true;
    }

    public void unsetDefault() {
        this.isDefault = false;
    }

    public void updateDetails(String name, String description) {
        if (name != null && !name.trim().isEmpty()) {
            this.name = name;
        }
        this.description = description;
    }

    public int getStepCount() {
        return steps != null ? steps.size() : 0;
    }
}
