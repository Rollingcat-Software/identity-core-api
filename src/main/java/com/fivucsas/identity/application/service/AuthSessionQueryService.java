package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.AuthSessionListItemResponse;
import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.repository.AuthSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Read-only query service backing the admin auth-sessions list endpoint.
 *
 * <p>Tenant-scope contract (Copilot post-merge round 5 doc update):
 * <ul>
 *   <li>Tenant-scoped callers MUST pass their own {@code tenantId}; the
 *       controller enforces this by deriving {@code tenantId} from the
 *       caller's RBAC scope.</li>
 *   <li>ROOT MAY pass {@code tenantId = null} to request a
 *       platform-wide cross-tenant listing. In that case this service runs
 *       non-tenant-scoped repository queries. Authorization (i.e. the
 *       caller is actually ROOT) MUST be enforced by the controller
 *       BEFORE invoking this service — this layer trusts that check.</li>
 * </ul>
 * Status and user filters are optional. Maps to the safe-fields DTO
 * {@link AuthSessionListItemResponse}.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class AuthSessionQueryService {

    /** Hard cap to prevent operators from accidentally dumping a million rows. */
    private static final int MAX_PAGE_SIZE = 200;

    private final AuthSessionRepository authSessionRepository;

    /**
     * Paginated list of auth sessions.
     *
     * @param tenantId      tenant whose sessions are returned. Pass
     *                      {@code null} ONLY for ROOT platform-wide
     *                      listings; the controller MUST verify ROOT
     *                      role before calling with {@code null}.
     * @param statusFilter  optional list of statuses to include (null/empty
     *                      means all statuses)
     * @param userId        optional userId to further restrict to a single user
     * @param page          0-based page number
     * @param size          rows per page (capped at {@link #MAX_PAGE_SIZE})
     */
    public Map<String, Object> listForTenant(
            UUID tenantId,
            List<AuthSessionStatus> statusFilter,
            UUID userId,
            int page,
            int size) {

        int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        int safePage = Math.max(page, 0);
        Pageable pageable = PageRequest.of(safePage, safeSize,
                Sort.by(Sort.Direction.DESC, "startedAt"));

        boolean hasStatusFilter = statusFilter != null && !statusFilter.isEmpty();
        boolean hasUserFilter = userId != null;
        boolean hasTenantFilter = tenantId != null;

        Page<AuthSession> result;
        if (!hasTenantFilter) {
            // ROOT platform-wide listing — caller scope already
            // verified by the controller; tenant filter intentionally absent.
            if (hasUserFilter && hasStatusFilter) {
                result = authSessionRepository.findAllByUserIdAndStatusIn(userId, statusFilter, pageable);
            } else if (hasUserFilter) {
                result = authSessionRepository.findAllByUserId(userId, pageable);
            } else if (hasStatusFilter) {
                result = authSessionRepository.findAllByStatusIn(statusFilter, pageable);
            } else {
                result = authSessionRepository.findAll(pageable);
            }
        } else if (hasUserFilter && hasStatusFilter) {
            result = authSessionRepository.findAllByTenantIdAndUserIdAndStatusIn(
                    tenantId, userId, statusFilter, pageable);
        } else if (hasUserFilter) {
            result = authSessionRepository.findAllByTenantIdAndUserId(
                    tenantId, userId, pageable);
        } else if (hasStatusFilter) {
            result = authSessionRepository.findAllByTenantIdAndStatusIn(
                    tenantId, statusFilter, pageable);
        } else {
            result = authSessionRepository.findAllByTenantId(tenantId, pageable);
        }

        List<AuthSessionListItemResponse> items = result.getContent().stream()
                .map(AuthSessionListItemResponse::from)
                .toList();

        return Map.of(
                "content", items,
                "totalElements", result.getTotalElements(),
                "totalPages", result.getTotalPages(),
                "page", result.getNumber(),
                "size", result.getSize()
        );
    }
}
