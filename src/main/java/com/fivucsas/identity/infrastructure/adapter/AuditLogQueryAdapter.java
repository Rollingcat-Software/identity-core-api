package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuditLogQueryPort;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * Infrastructure adapter implementing AuditLogQueryPort.
 * Delegates to the Spring Data JPA AuditLogRepository.
 */
@Repository
@RequiredArgsConstructor
public class AuditLogQueryAdapter implements AuditLogQueryPort {

    private final AuditLogRepository auditLogRepository;

    @Override
    public Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable) {
        return auditLogRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
    }

    @Override
    public Page<AuditLog> findByUserIdAndActionOrderByCreatedAtDesc(UUID userId, String action, Pageable pageable) {
        return auditLogRepository.findByUserIdAndActionOrderByCreatedAtDesc(userId, action, pageable);
    }

    @Override
    public Page<AuditLog> findByTenantIdOrderByCreatedAtDesc(UUID tenantId, Pageable pageable) {
        return auditLogRepository.findByTenantIdOrderByCreatedAtDesc(tenantId, pageable);
    }

    @Override
    public Page<AuditLog> findByTenantIdAndActionOrderByCreatedAtDesc(UUID tenantId, String action, Pageable pageable) {
        return auditLogRepository.findByTenantIdAndActionOrderByCreatedAtDesc(tenantId, action, pageable);
    }

    @Override
    public Page<AuditLog> findBySuccessOrderByCreatedAtDesc(Boolean success, Pageable pageable) {
        return auditLogRepository.findBySuccessOrderByCreatedAtDesc(success, pageable);
    }

    @Override
    public long count() {
        return auditLogRepository.count();
    }
}
