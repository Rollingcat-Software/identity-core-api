package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

/**
 * Output port for querying audit logs from the application layer.
 *
 * Follows Dependency Inversion: application defines the contract,
 * infrastructure provides the implementation.
 */
public interface AuditLogQueryPort {

    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    Page<AuditLog> findByUserIdAndActionOrderByCreatedAtDesc(UUID userId, String action, Pageable pageable);

    Page<AuditLog> findByTenantIdOrderByCreatedAtDesc(UUID tenantId, Pageable pageable);

    Page<AuditLog> findByTenantIdAndActionOrderByCreatedAtDesc(UUID tenantId, String action, Pageable pageable);

    Page<AuditLog> findBySuccessOrderByCreatedAtDesc(Boolean success, Pageable pageable);

    long count();
}
