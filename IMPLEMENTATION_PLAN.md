# Identity Core API - Complete Implementation Plan

## Overview

| Attribute | Value |
|-----------|-------|
| **Module** | Identity Core API |
| **Technology** | Spring Boot 3.2, Java 21 |
| **Architecture** | Hexagonal (Ports & Adapters) |
| **Current Completion** | 68% |
| **Target Completion** | 100% |
| **Port** | 8080 |

## Purpose

Central authentication and identity management service for FIVUCSAS platform. Provides:
- User authentication (JWT)
- User management (CRUD)
- Role-Based Access Control (RBAC)
- Multi-tenant support
- Biometric integration (proxies to Biometric Processor)
- Audit logging

---

## External Dependencies

### Services This Module Calls
| Service | URL | Purpose |
|---------|-----|---------|
| Biometric Processor | `http://localhost:8001` | Face enrollment/verification |
| PostgreSQL | `localhost:5432` | Primary database |
| Redis | `localhost:6379` | Cache, session, rate limiting |

### Services That Call This Module
| Client | Endpoints Used |
|--------|----------------|
| Web App | `/api/v1/auth/*`, `/api/v1/users/*`, `/api/v1/statistics/*` |
| Mobile Apps | `/api/v1/auth/*`, `/api/v1/biometric/*` |
| Desktop App | `/api/v1/auth/*`, `/api/v1/users/*`, `/api/v1/audit/*` |

---

## Current Architecture

```
src/main/java/com/fivucsas/identity/
├── domain/                      # Business logic (NO external dependencies)
│   ├── exception/              # 15 domain exceptions (sealed hierarchy)
│   ├── model/                  # User, Tenant, Role, Permission + 7 value objects
│   └── repository/             # Repository interfaces
├── application/                 # Use cases
│   ├── port/input/             # 11 use case interfaces
│   ├── port/output/            # 5 output port interfaces
│   ├── service/                # 11 use case implementations
│   └── dto/                    # Commands, queries, responses
├── infrastructure/              # External adapters
│   ├── adapter/                # BiometricService, TokenGeneration, PasswordEncoder, AuditLog
│   ├── persistence/            # 7 JPA converters
│   ├── multitenancy/           # TenantContext, filters, aspects
│   ├── messaging/              # Redis event bus
│   └── security/               # JWT, authentication
├── controller/                  # 8 REST controllers
├── entity/                      # JPA entities
├── config/                      # Spring configurations
└── repository/                  # Spring Data JPA repositories
```

---

## API Endpoints

### Authentication
```
POST /api/v1/auth/register        # User registration
POST /api/v1/auth/login           # Login (returns JWT tokens)
POST /api/v1/auth/logout          # Logout (invalidate token)
POST /api/v1/auth/refresh         # Refresh access token
GET  /api/v1/auth/me              # Current user info
POST /api/v1/auth/forgot-password # Request password reset
POST /api/v1/auth/reset-password  # Reset password with token
POST /api/v1/auth/change-password # Change password (authenticated)
```

### User Management
```
GET    /api/v1/users              # List users (paginated, filtered)
GET    /api/v1/users/{id}         # Get user by ID
POST   /api/v1/users              # Create user
PUT    /api/v1/users/{id}         # Update user
DELETE /api/v1/users/{id}         # Delete user
PATCH  /api/v1/users/{id}/status  # Change user status
GET    /api/v1/users/search       # Search users
```

### User Settings
```
GET  /api/v1/users/me/settings       # Get current user settings
PUT  /api/v1/users/me/profile        # Update profile
PUT  /api/v1/users/me/security       # Update security settings
PUT  /api/v1/users/me/notifications  # Update notification preferences
PUT  /api/v1/users/me/appearance     # Update appearance preferences
```

### Tenant Management
```
GET    /api/v1/tenants            # List tenants (super admin)
GET    /api/v1/tenants/{id}       # Get tenant
POST   /api/v1/tenants            # Create tenant
PUT    /api/v1/tenants/{id}       # Update tenant
DELETE /api/v1/tenants/{id}       # Delete tenant
PATCH  /api/v1/tenants/{id}/status # Change tenant status
```

### Role & Permission Management
```
GET    /api/v1/roles              # List roles
GET    /api/v1/roles/{id}         # Get role with permissions
POST   /api/v1/roles              # Create role
PUT    /api/v1/roles/{id}         # Update role
DELETE /api/v1/roles/{id}         # Delete role
POST   /api/v1/roles/{id}/permissions # Add permissions to role
DELETE /api/v1/roles/{id}/permissions/{permId} # Remove permission

GET    /api/v1/permissions        # List all permissions

POST   /api/v1/users/{id}/roles   # Assign role to user
DELETE /api/v1/users/{id}/roles/{roleId} # Remove role from user
```

### Biometric (Proxy to Biometric Processor)
```
POST /api/v1/biometric/enroll     # Enroll face
POST /api/v1/biometric/verify     # Verify face
GET  /api/v1/biometric/status     # Get enrollment status
DELETE /api/v1/biometric/{userId} # Delete enrollment
```

### Statistics & Audit
```
GET /api/v1/statistics            # Dashboard statistics
GET /api/v1/statistics/export     # Export statistics

GET /api/v1/audit-logs            # List audit logs (paginated, filtered)
GET /api/v1/audit-logs/{id}       # Get audit log detail
GET /api/v1/audit-logs/export     # Export audit logs
```

---

## Implementation Phases

### PHASE 1: RBAC Enforcement (Priority: CRITICAL)

**Current State**: Schema exists, permissions defined, but not enforced
**Target**: All endpoints protected with proper authorization

#### Task 1.1: Enable Method Security
**File**: `src/main/java/com/fivucsas/identity/config/SecurityConfig.java`

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)  // ADD THIS LINE
public class SecurityConfig {
    // existing configuration...
}
```

#### Task 1.2: Create Authorization Service
**File**: `src/main/java/com/fivucsas/identity/security/AuthorizationService.java`

```java
@Service("authz")
@RequiredArgsConstructor
public class AuthorizationService {

    public boolean isOwner(UUID resourceId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth.getPrincipal() instanceof CustomUserDetails details) {
            return details.getUserId().equals(resourceId);
        }
        return false;
    }

    public boolean isSameTenant(UUID tenantId) {
        return TenantContext.getCurrentTenant()
            .map(t -> t.equals(tenantId))
            .orElse(false);
    }

    public boolean canManageUser(UUID targetUserId, UserRepository userRepository) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth.getPrincipal() instanceof CustomUserDetails details) {
            // Super admin can manage anyone
            if (hasRole("SUPER_ADMIN")) return true;

            // Tenant admin can manage users in their tenant
            if (hasRole("TENANT_ADMIN")) {
                return userRepository.findById(targetUserId)
                    .map(user -> user.getTenantId().equals(details.getTenantId()))
                    .orElse(false);
            }

            // Users can only manage themselves
            return details.getUserId().equals(targetUserId);
        }
        return false;
    }

    public boolean hasRole(String role) {
        return SecurityContextHolder.getContext().getAuthentication()
            .getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + role));
    }

    public boolean hasPermission(String permission) {
        return SecurityContextHolder.getContext().getAuthentication()
            .getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals(permission));
    }
}
```

#### Task 1.3: Add @PreAuthorize to All Controllers
**Files**: All controllers in `src/main/java/com/fivucsas/identity/controller/`

**UserController.java**:
```java
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    @GetMapping
    @PreAuthorize("hasAuthority('user:read') or hasRole('ADMIN') or hasRole('TENANT_ADMIN')")
    public ResponseEntity<Page<UserResponse>> getAllUsers(Pageable pageable) { ... }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('user:read') or @authz.isOwner(#id)")
    public ResponseEntity<UserResponse> getUser(@PathVariable UUID id) { ... }

    @PostMapping
    @PreAuthorize("hasAuthority('user:create') or hasRole('ADMIN')")
    public ResponseEntity<UserResponse> createUser(@RequestBody @Valid CreateUserCommand cmd) { ... }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('user:update') or @authz.isOwner(#id)")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable UUID id,
            @RequestBody @Valid UpdateUserCommand cmd) { ... }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('TENANT_ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id) { ... }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('TENANT_ADMIN')")
    public ResponseEntity<UserResponse> changeStatus(
            @PathVariable UUID id,
            @RequestBody ChangeStatusCommand cmd) { ... }
}
```

**TenantController.java**:
```java
@RestController
@RequestMapping("/api/v1/tenants")
@RequiredArgsConstructor
public class TenantController {

    @GetMapping
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Page<TenantResponse>> getAllTenants(Pageable pageable) { ... }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN') or @authz.isSameTenant(#id)")
    public ResponseEntity<TenantResponse> getTenant(@PathVariable UUID id) { ... }

    @PostMapping
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<TenantResponse> createTenant(@RequestBody @Valid CreateTenantCommand cmd) { ... }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<TenantResponse> updateTenant(
            @PathVariable UUID id,
            @RequestBody @Valid UpdateTenantCommand cmd) { ... }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> deleteTenant(@PathVariable UUID id) { ... }
}
```

**RoleController.java**:
```java
@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
public class RoleController {

    @GetMapping
    @PreAuthorize("hasAuthority('role:read') or hasRole('ADMIN')")
    public ResponseEntity<List<RoleResponse>> getAllRoles() { ... }

    @PostMapping
    @PreAuthorize("hasAuthority('role:create') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<RoleResponse> createRole(@RequestBody @Valid CreateRoleCommand cmd) { ... }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('role:update') or hasRole('SUPER_ADMIN')")
    public ResponseEntity<RoleResponse> updateRole(
            @PathVariable UUID id,
            @RequestBody @Valid UpdateRoleCommand cmd) { ... }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> deleteRole(@PathVariable UUID id) { ... }

    @PostMapping("/{id}/permissions")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<RoleResponse> addPermissions(
            @PathVariable UUID id,
            @RequestBody List<UUID> permissionIds) { ... }
}
```

**BiometricController.java**:
```java
@RestController
@RequestMapping("/api/v1/biometric")
@RequiredArgsConstructor
public class BiometricController {

    @PostMapping(value = "/enroll", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAuthority('biometric:enroll') or @authz.isOwner(#userId)")
    public ResponseEntity<EnrollmentResponse> enrollFace(
            @RequestParam("image") MultipartFile image,
            @RequestParam(value = "userId", required = false) UUID userId,
            @AuthenticationPrincipal CustomUserDetails user) { ... }

    @PostMapping(value = "/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAuthority('biometric:verify')")
    public ResponseEntity<VerificationResponse> verifyFace(
            @RequestParam("image") MultipartFile image,
            @RequestParam("userId") UUID userId) { ... }

    @GetMapping("/status")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<BiometricStatusResponse> getStatus(
            @AuthenticationPrincipal CustomUserDetails user) { ... }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('biometric:delete') or @authz.isOwner(#userId)")
    public ResponseEntity<Void> deleteEnrollment(@PathVariable UUID userId) { ... }
}
```

**StatisticsController.java**:
```java
@RestController
@RequestMapping("/api/v1/statistics")
@RequiredArgsConstructor
public class StatisticsController {

    @GetMapping
    @PreAuthorize("hasAuthority('analytics:view') or hasRole('ADMIN')")
    public ResponseEntity<StatisticsResponse> getStatistics() { ... }

    @GetMapping("/export")
    @PreAuthorize("hasAuthority('analytics:view') or hasRole('ADMIN')")
    public ResponseEntity<byte[]> exportStatistics(@RequestParam String format) { ... }
}
```

**AuditLogController.java**:
```java
@RestController
@RequestMapping("/api/v1/audit-logs")
@RequiredArgsConstructor
public class AuditLogController {

    @GetMapping
    @PreAuthorize("hasAuthority('audit:view') or hasRole('ADMIN')")
    public ResponseEntity<Page<AuditLogResponse>> getAuditLogs(
            Pageable pageable,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) LocalDateTime from,
            @RequestParam(required = false) LocalDateTime to) { ... }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('audit:view') or hasRole('ADMIN')")
    public ResponseEntity<AuditLogDetailResponse> getAuditLog(@PathVariable UUID id) { ... }

    @GetMapping("/export")
    @PreAuthorize("hasAuthority('audit:view') or hasRole('ADMIN')")
    public ResponseEntity<byte[]> exportAuditLogs(
            @RequestParam String format,
            @RequestParam(required = false) LocalDateTime from,
            @RequestParam(required = false) LocalDateTime to) { ... }
}
```

#### Task 1.4: Update CustomUserDetailsService
**File**: `src/main/java/com/fivucsas/identity/security/CustomUserDetailsService.java`

```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(Email.of(email))
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        Set<GrantedAuthority> authorities = new HashSet<>();

        // Add roles with ROLE_ prefix
        user.getActiveRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));

            // Add permissions from each role
            role.getPermissions().forEach(permission ->
                authorities.add(new SimpleGrantedAuthority(permission.getCode()))
            );
        });

        return new CustomUserDetails(
            user.getId(),
            user.getEmail().getValue(),
            user.getHashedPassword().getValue(),
            user.getTenantId(),
            user.getStatus() == UserStatus.ACTIVE,
            authorities
        );
    }
}
```

---

### PHASE 2: Multi-Tenancy Enforcement (Priority: CRITICAL)

#### Task 2.1: Implement TenantContextFilter
**File**: `src/main/java/com/fivucsas/identity/infrastructure/multitenancy/TenantContextFilter.java`

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class TenantContextFilter extends OncePerRequestFilter {

    private static final Set<String> PUBLIC_PATHS = Set.of(
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        "/api/v1/auth/forgot-password",
        "/api/v1/auth/reset-password",
        "/swagger-ui",
        "/api-docs",
        "/actuator"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            String path = request.getRequestURI();

            // Skip tenant check for public paths
            if (isPublicPath(path)) {
                chain.doFilter(request, response);
                return;
            }

            // Try to extract tenant from header
            String tenantHeader = request.getHeader("X-Tenant-ID");
            if (tenantHeader != null && !tenantHeader.isBlank()) {
                try {
                    UUID tenantId = UUID.fromString(tenantHeader);
                    TenantContext.setCurrentTenant(tenantId);
                } catch (IllegalArgumentException e) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid tenant ID format");
                    return;
                }
            }
            // Or extract from authenticated user
            else {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null && auth.getPrincipal() instanceof CustomUserDetails details) {
                    TenantContext.setCurrentTenant(details.getTenantId());
                }
            }

            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }
}
```

#### Task 2.2: Implement Hibernate Tenant Filter Aspect
**File**: `src/main/java/com/fivucsas/identity/infrastructure/multitenancy/TenantFilterAspect.java`

```java
@Aspect
@Component
@RequiredArgsConstructor
public class TenantFilterAspect {

    private final EntityManager entityManager;

    @Before("execution(* com.fivucsas.identity.repository.*.*(..))")
    public void enableTenantFilter(JoinPoint joinPoint) {
        if (TenantContext.hasTenant()) {
            Session session = entityManager.unwrap(Session.class);
            Filter filter = session.enableFilter("tenantFilter");
            filter.setParameter("tenantId", TenantContext.requireCurrentTenant());
        }
    }
}
```

#### Task 2.3: Verify Tenant Filter on Entities
**File**: Verify all tenant-scoped entities have the filter

```java
// UserEntity.java
@Entity
@Table(name = "users")
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = UUID.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class UserEntity { ... }

// RoleEntity.java
@Entity
@Table(name = "roles")
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = UUID.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class RoleEntity { ... }

// BiometricDataEntity.java - same pattern
// AuditLogEntity.java - same pattern
```

---

### PHASE 3: Biometric Integration (Priority: HIGH)

#### Task 3.1: Complete BiometricServiceAdapter
**File**: `src/main/java/com/fivucsas/identity/infrastructure/adapter/BiometricServiceAdapter.java`

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class BiometricServiceAdapter implements BiometricServicePort {

    private final WebClient webClient;

    @Value("${biometric.service.url}")
    private String biometricServiceUrl;

    @Override
    @CircuitBreaker(name = "biometricService", fallbackMethod = "enrollFallback")
    @Retry(name = "biometricService")
    public Mono<EnrollmentResult> enrollFace(UUID userId, UUID tenantId, byte[] imageData) {
        return webClient.post()
            .uri(biometricServiceUrl + "/api/v1/enroll")
            .header("X-Tenant-ID", tenantId.toString())
            .contentType(MediaType.MULTIPART_FORM_DATA)
            .body(BodyInserters.fromMultipartData(buildEnrollRequest(userId, imageData)))
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handleClientError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handleServerError)
            .bodyToMono(BiometricEnrollResponse.class)
            .map(this::toEnrollmentResult)
            .timeout(Duration.ofSeconds(30))
            .doOnSuccess(r -> log.info("Enrollment successful for user {}", userId))
            .doOnError(e -> log.error("Enrollment failed for user {}: {}", userId, e.getMessage()));
    }

    @Override
    @CircuitBreaker(name = "biometricService", fallbackMethod = "verifyFallback")
    @Retry(name = "biometricService")
    public Mono<VerificationResult> verifyFace(UUID userId, UUID tenantId, byte[] imageData) {
        return webClient.post()
            .uri(biometricServiceUrl + "/api/v1/verify")
            .header("X-Tenant-ID", tenantId.toString())
            .contentType(MediaType.MULTIPART_FORM_DATA)
            .body(BodyInserters.fromMultipartData(buildVerifyRequest(userId, imageData)))
            .retrieve()
            .bodyToMono(BiometricVerifyResponse.class)
            .map(this::toVerificationResult)
            .timeout(Duration.ofSeconds(30));
    }

    @Override
    public Mono<BiometricStatus> getEnrollmentStatus(UUID userId, UUID tenantId) {
        return webClient.get()
            .uri(biometricServiceUrl + "/api/v1/enrollments/{userId}/status", userId)
            .header("X-Tenant-ID", tenantId.toString())
            .retrieve()
            .bodyToMono(BiometricStatusResponse.class)
            .map(this::toBiometricStatus)
            .onErrorReturn(BiometricStatus.notEnrolled());
    }

    @Override
    public Mono<Void> deleteEnrollment(UUID userId, UUID tenantId) {
        return webClient.delete()
            .uri(biometricServiceUrl + "/api/v1/enrollments/{userId}", userId)
            .header("X-Tenant-ID", tenantId.toString())
            .retrieve()
            .bodyToMono(Void.class);
    }

    private MultiValueMap<String, Object> buildEnrollRequest(UUID userId, byte[] imageData) {
        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("user_id", userId.toString());
        builder.part("image", new ByteArrayResource(imageData) {
            @Override
            public String getFilename() {
                return "face.jpg";
            }
        }).contentType(MediaType.IMAGE_JPEG);
        return builder.build();
    }

    private MultiValueMap<String, Object> buildVerifyRequest(UUID userId, byte[] imageData) {
        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("user_id", userId.toString());
        builder.part("image", new ByteArrayResource(imageData) {
            @Override
            public String getFilename() {
                return "face.jpg";
            }
        }).contentType(MediaType.IMAGE_JPEG);
        return builder.build();
    }

    private Mono<Throwable> handleClientError(ClientResponse response) {
        return response.bodyToMono(BiometricErrorResponse.class)
            .flatMap(error -> Mono.error(new BiometricException(error.getMessage(), error.getCode())));
    }

    private Mono<Throwable> handleServerError(ClientResponse response) {
        return Mono.error(new BiometricServiceUnavailableException("Biometric service unavailable"));
    }

    private EnrollmentResult toEnrollmentResult(BiometricEnrollResponse response) {
        return EnrollmentResult.builder()
            .success(response.isSuccess())
            .enrollmentId(response.getEnrollmentId())
            .qualityScore(response.getQualityScore())
            .message(response.getMessage())
            .build();
    }

    private VerificationResult toVerificationResult(BiometricVerifyResponse response) {
        return VerificationResult.builder()
            .verified(response.isVerified())
            .confidence(response.getConfidence())
            .userId(response.getUserId())
            .message(response.getMessage())
            .build();
    }

    // Fallback methods
    private Mono<EnrollmentResult> enrollFallback(UUID userId, UUID tenantId, byte[] imageData, Throwable t) {
        log.warn("Enrollment fallback triggered for user {}: {}", userId, t.getMessage());
        return Mono.just(EnrollmentResult.failure("Biometric service temporarily unavailable"));
    }

    private Mono<VerificationResult> verifyFallback(UUID userId, UUID tenantId, byte[] imageData, Throwable t) {
        log.warn("Verification fallback triggered for user {}: {}", userId, t.getMessage());
        return Mono.just(VerificationResult.failure("Biometric service temporarily unavailable"));
    }
}
```

#### Task 3.2: Add Resilience4j Configuration
**File**: `src/main/resources/application.yml`

```yaml
resilience4j:
  circuitbreaker:
    instances:
      biometricService:
        slidingWindowSize: 10
        failureRateThreshold: 50
        waitDurationInOpenState: 30s
        permittedNumberOfCallsInHalfOpenState: 3
        slowCallDurationThreshold: 10s
        slowCallRateThreshold: 50
  retry:
    instances:
      biometricService:
        maxAttempts: 3
        waitDuration: 1s
        exponentialBackoffMultiplier: 2
        retryExceptions:
          - java.net.ConnectException
          - java.net.SocketTimeoutException
```

---

### PHASE 4: Audit Logging (Priority: HIGH)

#### Task 4.1: Create AuditLogEntity
**File**: `src/main/java/com/fivucsas/identity/entity/AuditLogEntity.java`

```java
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_tenant", columnList = "tenant_id"),
    @Index(name = "idx_audit_user", columnList = "user_id"),
    @Index(name = "idx_audit_action", columnList = "action"),
    @Index(name = "idx_audit_created", columnList = "created_at")
})
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = UUID.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "user_email")
    private String userEmail;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private AuditAction action;

    @Column(name = "resource_type")
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @Column(columnDefinition = "jsonb")
    @Convert(converter = JsonMapConverter.class)
    private Map<String, Object> details;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "request_id")
    private String requestId;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}

// AuditAction enum
public enum AuditAction {
    // Authentication
    USER_LOGIN,
    USER_LOGOUT,
    USER_LOGIN_FAILED,
    TOKEN_REFRESH,
    PASSWORD_CHANGE,
    PASSWORD_RESET_REQUEST,
    PASSWORD_RESET,

    // User management
    USER_CREATED,
    USER_UPDATED,
    USER_DELETED,
    USER_STATUS_CHANGED,
    USER_ROLE_ASSIGNED,
    USER_ROLE_REMOVED,

    // Tenant management
    TENANT_CREATED,
    TENANT_UPDATED,
    TENANT_DELETED,
    TENANT_STATUS_CHANGED,

    // Role management
    ROLE_CREATED,
    ROLE_UPDATED,
    ROLE_DELETED,
    PERMISSION_ADDED,
    PERMISSION_REMOVED,

    // Biometric
    BIOMETRIC_ENROLLED,
    BIOMETRIC_VERIFIED,
    BIOMETRIC_VERIFICATION_FAILED,
    BIOMETRIC_DELETED,

    // Settings
    SETTINGS_UPDATED,
    SECURITY_SETTINGS_UPDATED
}
```

#### Task 4.2: Implement AuditLogAdapter
**File**: `src/main/java/com/fivucsas/identity/infrastructure/adapter/AuditLogAdapter.java`

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLogAdapter implements AuditLogPort {

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    @Override
    @Async("auditLogExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(AuditEvent event) {
        try {
            AuditLogEntity entity = AuditLogEntity.builder()
                .tenantId(event.getTenantId())
                .userId(event.getUserId())
                .userEmail(event.getUserEmail())
                .action(event.getAction())
                .resourceType(event.getResourceType())
                .resourceId(event.getResourceId())
                .details(event.getDetails())
                .ipAddress(event.getIpAddress())
                .userAgent(event.getUserAgent())
                .requestId(event.getRequestId())
                .success(event.isSuccess())
                .errorMessage(event.getErrorMessage())
                .build();

            auditLogRepository.save(entity);

            log.debug("Audit log saved: {} for user {} on {}/{}",
                event.getAction(), event.getUserId(), event.getResourceType(), event.getResourceId());
        } catch (Exception e) {
            // Don't let audit logging failures affect business operations
            log.error("Failed to save audit log: {}", e.getMessage(), e);
        }
    }

    @Override
    public Page<AuditLogEntity> findAuditLogs(AuditLogQuery query, Pageable pageable) {
        Specification<AuditLogEntity> spec = buildSpecification(query);
        return auditLogRepository.findAll(spec, pageable);
    }

    private Specification<AuditLogEntity> buildSpecification(AuditLogQuery query) {
        return (root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (query.getTenantId() != null) {
                predicates.add(cb.equal(root.get("tenantId"), query.getTenantId()));
            }
            if (query.getUserId() != null) {
                predicates.add(cb.equal(root.get("userId"), query.getUserId()));
            }
            if (query.getAction() != null) {
                predicates.add(cb.equal(root.get("action"), query.getAction()));
            }
            if (query.getResourceType() != null) {
                predicates.add(cb.equal(root.get("resourceType"), query.getResourceType()));
            }
            if (query.getFrom() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), query.getFrom()));
            }
            if (query.getTo() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), query.getTo()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
```

#### Task 4.3: Create Audit Logging Aspect
**File**: `src/main/java/com/fivucsas/identity/infrastructure/audit/AuditLoggingAspect.java`

```java
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLoggingAspect {

    private final AuditLogPort auditLog;
    private final HttpServletRequest request;

    @AfterReturning(pointcut = "@annotation(audited)", returning = "result")
    public void logSuccess(JoinPoint joinPoint, Audited audited, Object result) {
        logAuditEvent(joinPoint, audited, true, null);
    }

    @AfterThrowing(pointcut = "@annotation(audited)", throwing = "ex")
    public void logFailure(JoinPoint joinPoint, Audited audited, Exception ex) {
        logAuditEvent(joinPoint, audited, false, ex.getMessage());
    }

    private void logAuditEvent(JoinPoint joinPoint, Audited audited, boolean success, String errorMessage) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails user = auth != null && auth.getPrincipal() instanceof CustomUserDetails
            ? (CustomUserDetails) auth.getPrincipal()
            : null;

        AuditEvent event = AuditEvent.builder()
            .tenantId(TenantContext.getCurrentTenant().orElse(null))
            .userId(user != null ? user.getUserId() : null)
            .userEmail(user != null ? user.getEmail() : null)
            .action(audited.action())
            .resourceType(audited.resourceType())
            .resourceId(extractResourceId(joinPoint, audited))
            .details(extractDetails(joinPoint, audited))
            .ipAddress(getClientIp())
            .userAgent(request.getHeader("User-Agent"))
            .requestId(MDC.get("requestId"))
            .success(success)
            .errorMessage(errorMessage)
            .build();

        auditLog.log(event);
    }

    private String getClientIp() {
        String xff = request.getHeader("X-Forwarded-For");
        return xff != null ? xff.split(",")[0].trim() : request.getRemoteAddr();
    }

    private String extractResourceId(JoinPoint joinPoint, Audited audited) {
        // Extract ID from method parameters based on annotation configuration
        // ...
    }

    private Map<String, Object> extractDetails(JoinPoint joinPoint, Audited audited) {
        // Extract relevant details from method parameters
        // ...
    }
}

// Audited annotation
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    AuditAction action();
    String resourceType() default "";
    String resourceIdParam() default "id";
    String[] includeParams() default {};
}
```

#### Task 4.4: Apply @Audited to Service Methods
**Example usage in services**:

```java
@Service
@RequiredArgsConstructor
public class RegisterUserService implements RegisterUserUseCase {

    @Override
    @Transactional
    @Audited(action = AuditAction.USER_CREATED, resourceType = "User")
    public UserResponse execute(RegisterUserCommand command) {
        // ... implementation
    }
}

@Service
@RequiredArgsConstructor
public class AuthenticateUserService implements AuthenticateUserUseCase {

    @Override
    @Audited(action = AuditAction.USER_LOGIN, resourceType = "User")
    public AuthResponse execute(LoginCommand command) {
        // ... implementation
    }
}
```

---

### PHASE 5: User Settings & Password Management (Priority: HIGH)

#### Task 5.1: Create UserSettings Entity
**File**: `src/main/java/com/fivucsas/identity/entity/UserSettingsEntity.java`

```java
@Entity
@Table(name = "user_settings")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSettingsEntity {

    @Id
    private UUID userId;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "user_id")
    private UserEntity user;

    // Security settings
    @Column(name = "two_factor_enabled")
    private boolean twoFactorEnabled = false;

    @Column(name = "two_factor_secret")
    private String twoFactorSecret;

    @Column(name = "session_timeout")
    private int sessionTimeout = 30; // minutes

    // Notification settings
    @Column(name = "email_notifications")
    private boolean emailNotifications = true;

    @Column(name = "login_alerts")
    private boolean loginAlerts = true;

    @Column(name = "security_alerts")
    private boolean securityAlerts = true;

    @Column(name = "weekly_reports")
    private boolean weeklyReports = false;

    // Appearance settings
    @Column(name = "dark_mode")
    private boolean darkMode = false;

    @Column(name = "compact_view")
    private boolean compactView = false;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
```

#### Task 5.2: Add Database Migration
**File**: `src/main/resources/db/migration/V10__create_user_settings.sql`

```sql
CREATE TABLE user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    session_timeout INTEGER DEFAULT 30,
    email_notifications BOOLEAN DEFAULT TRUE,
    login_alerts BOOLEAN DEFAULT TRUE,
    security_alerts BOOLEAN DEFAULT TRUE,
    weekly_reports BOOLEAN DEFAULT FALSE,
    dark_mode BOOLEAN DEFAULT FALSE,
    compact_view BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP
);

-- Create default settings for existing users
INSERT INTO user_settings (user_id)
SELECT id FROM users
ON CONFLICT DO NOTHING;
```

#### Task 5.3: Create Settings Service
**File**: `src/main/java/com/fivucsas/identity/application/service/UserSettingsService.java`

```java
@Service
@RequiredArgsConstructor
@Transactional
public class UserSettingsService implements ManageUserSettingsUseCase {

    private final UserSettingsRepository settingsRepository;
    private final UserRepository userRepository;

    @Override
    public UserSettingsResponse getSettings(UUID userId) {
        UserSettingsEntity settings = settingsRepository.findById(userId)
            .orElseGet(() -> createDefaultSettings(userId));

        UserEntity user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId));

        return UserSettingsResponse.builder()
            .profile(ProfileResponse.builder()
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail().getValue())
                .phone(user.getPhoneNumber() != null ? user.getPhoneNumber().getValue() : null)
                .build())
            .security(SecurityResponse.builder()
                .twoFactorEnabled(settings.isTwoFactorEnabled())
                .sessionTimeout(settings.getSessionTimeout())
                .build())
            .notifications(NotificationResponse.builder()
                .emailNotifications(settings.isEmailNotifications())
                .loginAlerts(settings.isLoginAlerts())
                .securityAlerts(settings.isSecurityAlerts())
                .weeklyReports(settings.isWeeklyReports())
                .build())
            .appearance(AppearanceResponse.builder()
                .darkMode(settings.isDarkMode())
                .compactView(settings.isCompactView())
                .build())
            .build();
    }

    @Override
    @Audited(action = AuditAction.SETTINGS_UPDATED, resourceType = "UserSettings")
    public void updateProfile(UUID userId, UpdateProfileCommand command) {
        UserEntity user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId));

        user.setFirstName(command.getFirstName());
        user.setLastName(command.getLastName());
        if (command.getPhone() != null) {
            user.setPhoneNumber(PhoneNumber.of(command.getPhone()));
        }

        userRepository.save(user);
    }

    @Override
    @Audited(action = AuditAction.SECURITY_SETTINGS_UPDATED, resourceType = "UserSettings")
    public void updateSecurity(UUID userId, UpdateSecurityCommand command) {
        UserSettingsEntity settings = getOrCreateSettings(userId);

        if (command.getTwoFactorEnabled() != null) {
            settings.setTwoFactorEnabled(command.getTwoFactorEnabled());
        }
        if (command.getSessionTimeout() != null) {
            settings.setSessionTimeout(command.getSessionTimeout());
        }

        settingsRepository.save(settings);
    }

    @Override
    public void updateNotifications(UUID userId, UpdateNotificationsCommand command) {
        UserSettingsEntity settings = getOrCreateSettings(userId);

        settings.setEmailNotifications(command.isEmailNotifications());
        settings.setLoginAlerts(command.isLoginAlerts());
        settings.setSecurityAlerts(command.isSecurityAlerts());
        settings.setWeeklyReports(command.isWeeklyReports());

        settingsRepository.save(settings);
    }

    @Override
    public void updateAppearance(UUID userId, UpdateAppearanceCommand command) {
        UserSettingsEntity settings = getOrCreateSettings(userId);

        settings.setDarkMode(command.isDarkMode());
        settings.setCompactView(command.isCompactView());

        settingsRepository.save(settings);
    }

    private UserSettingsEntity createDefaultSettings(UUID userId) {
        UserSettingsEntity settings = UserSettingsEntity.builder()
            .userId(userId)
            .build();
        return settingsRepository.save(settings);
    }

    private UserSettingsEntity getOrCreateSettings(UUID userId) {
        return settingsRepository.findById(userId)
            .orElseGet(() -> createDefaultSettings(userId));
    }
}
```

#### Task 5.4: Implement Password Change
**File**: `src/main/java/com/fivucsas/identity/application/service/ChangePasswordService.java`

```java
@Service
@RequiredArgsConstructor
public class ChangePasswordService implements ChangePasswordUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final AuditLogPort auditLog;

    @Override
    @Transactional
    @Audited(action = AuditAction.PASSWORD_CHANGE, resourceType = "User")
    public void execute(UUID userId, ChangePasswordCommand command) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId));

        // Verify current password
        if (!passwordEncoder.matches(command.getCurrentPassword(), user.getHashedPassword().getValue())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Validate new password
        validateNewPassword(command.getNewPassword(), command.getCurrentPassword());

        // Update password
        String hashedPassword = passwordEncoder.encode(command.getNewPassword());
        user.changePassword(HashedPassword.of(hashedPassword));

        userRepository.save(user);
    }

    private void validateNewPassword(String newPassword, String currentPassword) {
        if (newPassword.equals(currentPassword)) {
            throw new ValidationException("New password must be different from current password");
        }

        if (newPassword.length() < 8) {
            throw new ValidationException("Password must be at least 8 characters");
        }

        if (!newPassword.matches(".*[A-Z].*")) {
            throw new ValidationException("Password must contain at least one uppercase letter");
        }

        if (!newPassword.matches(".*[a-z].*")) {
            throw new ValidationException("Password must contain at least one lowercase letter");
        }

        if (!newPassword.matches(".*\\d.*")) {
            throw new ValidationException("Password must contain at least one digit");
        }

        if (!newPassword.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            throw new ValidationException("Password must contain at least one special character");
        }
    }
}
```

#### Task 5.5: Create Settings Controller
**File**: `src/main/java/com/fivucsas/identity/controller/SettingsController.java`

```java
@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
public class SettingsController {

    private final ManageUserSettingsUseCase settingsUseCase;
    private final ChangePasswordUseCase changePasswordUseCase;

    @GetMapping("/settings")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserSettingsResponse> getSettings(
            @AuthenticationPrincipal CustomUserDetails user) {
        return ResponseEntity.ok(settingsUseCase.getSettings(user.getUserId()));
    }

    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateProfile(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid UpdateProfileCommand command) {
        settingsUseCase.updateProfile(user.getUserId(), command);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/security")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateSecurity(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid UpdateSecurityCommand command) {
        settingsUseCase.updateSecurity(user.getUserId(), command);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/notifications")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateNotifications(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid UpdateNotificationsCommand command) {
        settingsUseCase.updateNotifications(user.getUserId(), command);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/appearance")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateAppearance(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid UpdateAppearanceCommand command) {
        settingsUseCase.updateAppearance(user.getUserId(), command);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid ChangePasswordCommand command) {
        changePasswordUseCase.execute(user.getUserId(), command);
        return ResponseEntity.ok().build();
    }
}
```

---

### PHASE 6: Email Integration (Priority: MEDIUM)

#### Task 6.1: Create Email Service
**File**: `src/main/java/com/fivucsas/identity/infrastructure/adapter/EmailServiceAdapter.java`

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class EmailServiceAdapter implements EmailServicePort {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.mail.from}")
    private String fromAddress;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Override
    @Async("emailExecutor")
    public void sendPasswordResetEmail(String email, String resetToken) {
        Context context = new Context();
        context.setVariable("resetLink", frontendUrl + "/reset-password?token=" + resetToken);
        context.setVariable("expiresIn", "1 hour");

        sendEmail(email, "Reset Your Password - FIVUCSAS", "password-reset", context);
    }

    @Override
    @Async("emailExecutor")
    public void sendEmailVerification(String email, String verificationToken) {
        Context context = new Context();
        context.setVariable("verifyLink", frontendUrl + "/verify-email?token=" + verificationToken);

        sendEmail(email, "Verify Your Email - FIVUCSAS", "email-verification", context);
    }

    @Override
    @Async("emailExecutor")
    public void sendWelcomeEmail(String email, String userName) {
        Context context = new Context();
        context.setVariable("userName", userName);
        context.setVariable("loginLink", frontendUrl + "/login");

        sendEmail(email, "Welcome to FIVUCSAS", "welcome", context);
    }

    @Override
    @Async("emailExecutor")
    public void sendLoginAlert(String email, String ipAddress, String userAgent, LocalDateTime timestamp) {
        Context context = new Context();
        context.setVariable("ipAddress", ipAddress);
        context.setVariable("userAgent", userAgent);
        context.setVariable("timestamp", timestamp);

        sendEmail(email, "New Login Detected - FIVUCSAS", "login-alert", context);
    }

    private void sendEmail(String to, String subject, String templateName, Context context) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            String htmlContent = templateEngine.process(templateName, context);

            helper.setFrom(fromAddress);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Email sent successfully to {} with subject: {}", to, subject);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage());
        }
    }
}
```

#### Task 6.2: Create Email Templates
**File**: `src/main/resources/templates/password-reset.html`

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #1976d2; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; background: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background: #1976d2; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>FIVUCSAS</h1>
        </div>
        <div class="content">
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center;">
                <a th:href="${resetLink}" class="button">Reset Password</a>
            </p>
            <p>This link will expire in <strong th:text="${expiresIn}">1 hour</strong>.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; 2026 FIVUCSAS. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
```

#### Task 6.3: Implement Password Reset Flow
**File**: `src/main/java/com/fivucsas/identity/application/service/PasswordResetService.java`

```java
@Service
@RequiredArgsConstructor
public class PasswordResetService implements PasswordResetUseCase {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final EmailServicePort emailService;
    private final PasswordEncoderPort passwordEncoder;

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        userRepository.findByEmail(Email.of(email)).ifPresent(user -> {
            // Invalidate existing tokens
            tokenRepository.invalidateByUserId(user.getId());

            // Generate new token
            String token = UUID.randomUUID().toString();
            PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .userId(user.getId())
                .expiresAt(LocalDateTime.now().plusHours(1))
                .build();

            tokenRepository.save(resetToken);

            // Send email
            emailService.sendPasswordResetEmail(email, token);
        });

        // Always return success to prevent email enumeration
    }

    @Override
    @Transactional
    @Audited(action = AuditAction.PASSWORD_RESET, resourceType = "User")
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
            .filter(t -> !t.isUsed())
            .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
            .orElseThrow(() -> new TokenExpiredException("Invalid or expired reset token"));

        User user = userRepository.findById(resetToken.getUserId())
            .orElseThrow(() -> new UserNotFoundException(resetToken.getUserId()));

        // Update password
        String hashedPassword = passwordEncoder.encode(newPassword);
        user.changePassword(HashedPassword.of(hashedPassword));
        userRepository.save(user);

        // Mark token as used
        resetToken.markAsUsed();
        tokenRepository.save(resetToken);
    }
}
```

---

### PHASE 7: Rate Limiting (Priority: MEDIUM)

#### Task 7.1: Implement Rate Limiting with Bucket4j
**File**: `src/main/java/com/fivucsas/identity/infrastructure/ratelimit/RateLimitingFilter.java`

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
@RequiredArgsConstructor
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;

    private static final Map<String, RateLimitConfig> RATE_LIMITS = Map.of(
        "/api/v1/auth/login", new RateLimitConfig(5, Duration.ofMinutes(15)),      // 5 per 15 min
        "/api/v1/auth/register", new RateLimitConfig(3, Duration.ofHours(1)),      // 3 per hour
        "/api/v1/auth/forgot-password", new RateLimitConfig(3, Duration.ofHours(1)), // 3 per hour
        "DEFAULT", new RateLimitConfig(100, Duration.ofMinutes(1))                  // 100 per minute
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String clientId = getClientIdentifier(request);
        String path = request.getRequestURI();

        RateLimitConfig config = RATE_LIMITS.getOrDefault(path, RATE_LIMITS.get("DEFAULT"));

        RateLimitResult result = rateLimitService.tryConsume(clientId, path, config);

        response.setHeader("X-RateLimit-Limit", String.valueOf(config.getLimit()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(result.getRemainingTokens()));
        response.setHeader("X-RateLimit-Reset", String.valueOf(result.getResetTime()));

        if (!result.isAllowed()) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Rate limit exceeded. Try again later.\"}");
            return;
        }

        chain.doFilter(request, response);
    }

    private String getClientIdentifier(HttpServletRequest request) {
        // Use authenticated user ID if available
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails details) {
            return "user:" + details.getUserId();
        }

        // Fall back to IP address
        String xff = request.getHeader("X-Forwarded-For");
        String ip = xff != null ? xff.split(",")[0].trim() : request.getRemoteAddr();
        return "ip:" + ip;
    }
}
```

#### Task 7.2: Create Rate Limit Service with Redis Backend
**File**: `src/main/java/com/fivucsas/identity/infrastructure/ratelimit/RedisRateLimitService.java`

```java
@Service
@RequiredArgsConstructor
public class RedisRateLimitService implements RateLimitService {

    private final StringRedisTemplate redisTemplate;

    @Override
    public RateLimitResult tryConsume(String clientId, String endpoint, RateLimitConfig config) {
        String key = "ratelimit:" + clientId + ":" + endpoint;

        Long currentCount = redisTemplate.opsForValue().increment(key);

        if (currentCount == 1) {
            redisTemplate.expire(key, config.getWindow());
        }

        long remaining = Math.max(0, config.getLimit() - currentCount);
        long resetTime = redisTemplate.getExpire(key, TimeUnit.SECONDS);

        return RateLimitResult.builder()
            .allowed(currentCount <= config.getLimit())
            .remainingTokens(remaining)
            .resetTime(System.currentTimeMillis() / 1000 + resetTime)
            .build();
    }
}
```

---

### PHASE 8: Integration Tests (Priority: HIGH)

#### Task 8.1: Setup TestContainers
**File**: `src/test/java/com/fivucsas/identity/integration/TestContainersConfig.java`

```java
@TestConfiguration
public class TestContainersConfig {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("fivucsas_test")
        .withUsername("test")
        .withPassword("test");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
        .withExposedPorts(6379);

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("spring.flyway.enabled", () -> true);
    }

    static {
        postgres.start();
        redis.start();
    }
}
```

#### Task 8.2: Create Authentication Integration Tests
**File**: `src/test/java/com/fivucsas/identity/integration/AuthenticationIntegrationTest.java`

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestContainersConfig.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    private static String accessToken;
    private static String refreshToken;

    @Test
    @Order(1)
    void register_WithValidData_ShouldCreateUserAndReturnTokens() {
        RegisterRequest request = new RegisterRequest(
            "test@example.com", "Password123!", "John", "Doe"
        );

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
            "/api/v1/auth/register", request, AuthResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getAccessToken()).isNotBlank();
        assertThat(response.getBody().getRefreshToken()).isNotBlank();
        assertThat(response.getBody().getUser().getEmail()).isEqualTo("test@example.com");

        accessToken = response.getBody().getAccessToken();
        refreshToken = response.getBody().getRefreshToken();
    }

    @Test
    @Order(2)
    void login_WithValidCredentials_ShouldReturnTokens() {
        LoginRequest request = new LoginRequest("test@example.com", "Password123!");

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
            "/api/v1/auth/login", request, AuthResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getAccessToken()).isNotBlank();
    }

    @Test
    @Order(3)
    void login_WithInvalidCredentials_ShouldReturn401() {
        LoginRequest request = new LoginRequest("test@example.com", "WrongPassword");

        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
            "/api/v1/auth/login", request, ErrorResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Order(4)
    void getCurrentUser_WithValidToken_ShouldReturnUser() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        ResponseEntity<UserResponse> response = restTemplate.exchange(
            "/api/v1/auth/me",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            UserResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    @Order(5)
    void refreshToken_WithValidToken_ShouldReturnNewTokens() {
        RefreshTokenRequest request = new RefreshTokenRequest(refreshToken);

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
            "/api/v1/auth/refresh", request, AuthResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getAccessToken()).isNotBlank();
        assertThat(response.getBody().getAccessToken()).isNotEqualTo(accessToken);
    }
}
```

#### Task 8.3: Create RBAC Integration Tests
**File**: `src/test/java/com/fivucsas/identity/integration/RBACIntegrationTest.java`

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestContainersConfig.class)
class RBACIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void adminCanListAllUsers() {
        String adminToken = loginAsAdmin();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);

        ResponseEntity<Page<UserResponse>> response = restTemplate.exchange(
            "/api/v1/users",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            new ParameterizedTypeReference<>() {}
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void regularUserCannotListAllUsers() {
        String userToken = loginAsUser();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(userToken);

        ResponseEntity<ErrorResponse> response = restTemplate.exchange(
            "/api/v1/users",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            ErrorResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void userCanUpdateOwnProfile() {
        String userToken = loginAsUser();
        UUID userId = extractUserIdFromToken(userToken);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(userToken);

        UpdateUserCommand command = new UpdateUserCommand("John", "Updated", null);

        ResponseEntity<UserResponse> response = restTemplate.exchange(
            "/api/v1/users/" + userId,
            HttpMethod.PUT,
            new HttpEntity<>(command, headers),
            UserResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getLastName()).isEqualTo("Updated");
    }

    @Test
    void userCannotUpdateOtherUserProfile() {
        String userToken = loginAsUser();
        UUID otherUserId = createAnotherUser();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(userToken);

        UpdateUserCommand command = new UpdateUserCommand("Hacker", "Attack", null);

        ResponseEntity<ErrorResponse> response = restTemplate.exchange(
            "/api/v1/users/" + otherUserId,
            HttpMethod.PUT,
            new HttpEntity<>(command, headers),
            ErrorResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // Helper methods...
}
```

#### Task 8.4: Create Multi-Tenancy Integration Tests
**File**: `src/test/java/com/fivucsas/identity/integration/MultiTenancyIntegrationTest.java`

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestContainersConfig.class)
class MultiTenancyIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TenantRepository tenantRepository;

    @Test
    void tenantAdminCanOnlySeeUsersInOwnTenant() {
        // Create two tenants
        UUID tenantA = createTenant("Tenant A");
        UUID tenantB = createTenant("Tenant B");

        // Create users in each tenant
        createUserInTenant("userA@tenanta.com", tenantA);
        createUserInTenant("userB@tenantb.com", tenantB);

        // Login as Tenant A admin
        String tokenA = loginAsTenantAdmin(tenantA);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenA);
        headers.set("X-Tenant-ID", tenantA.toString());

        ResponseEntity<Page<UserResponse>> response = restTemplate.exchange(
            "/api/v1/users",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            new ParameterizedTypeReference<>() {}
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getContent())
            .allMatch(user -> user.getEmail().endsWith("@tenanta.com"));
    }

    @Test
    void userCannotAccessResourcesInOtherTenant() {
        UUID tenantA = createTenant("Tenant A");
        UUID tenantB = createTenant("Tenant B");

        UUID userInTenantB = createUserInTenant("target@tenantb.com", tenantB);

        String tokenA = loginAsTenantAdmin(tenantA);

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenA);
        headers.set("X-Tenant-ID", tenantA.toString());

        ResponseEntity<ErrorResponse> response = restTemplate.exchange(
            "/api/v1/users/" + userInTenantB,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            ErrorResponse.class
        );

        // Should return 404 (not found) because the user is filtered by tenant
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // Helper methods...
}
```

---

## Configuration

### application.yml (Complete)
```yaml
spring:
  application:
    name: identity-core-api

  datasource:
    url: jdbc:postgresql://${POSTGRES_HOST:localhost}:${POSTGRES_PORT:5432}/${POSTGRES_DB:fivucsas}
    username: ${POSTGRES_USER:fivucsas}
    password: ${POSTGRES_PASSWORD:}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000

  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true

  flyway:
    enabled: true
    locations: classpath:db/migration

  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD:}

  mail:
    host: ${SMTP_HOST:smtp.gmail.com}
    port: ${SMTP_PORT:587}
    username: ${SMTP_USER:}
    password: ${SMTP_PASSWORD:}
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true

biometric:
  service:
    url: ${BIOMETRIC_SERVICE_URL:http://localhost:8001}

jwt:
  secret: ${JWT_SECRET:}
  access-expiration: ${JWT_ACCESS_EXPIRATION:3600}
  refresh-expiration: ${JWT_REFRESH_EXPIRATION:604800}

app:
  mail:
    from: ${MAIL_FROM:noreply@fivucsas.com}
  frontend:
    url: ${FRONTEND_URL:http://localhost:5173}

server:
  port: 8080

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: when_authorized

logging:
  level:
    com.fivucsas: DEBUG
    org.hibernate.SQL: DEBUG
```

### pom.xml Dependencies to Add
```xml
<!-- Resilience4j -->
<dependency>
    <groupId>io.github.resilience4j</groupId>
    <artifactId>resilience4j-spring-boot3</artifactId>
    <version>2.2.0</version>
</dependency>

<!-- Email -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
</dependency>
<dependency>
    <groupId>org.thymeleaf</groupId>
    <artifactId>thymeleaf-spring6</artifactId>
</dependency>

<!-- TestContainers -->
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>postgresql</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>junit-jupiter</artifactId>
    <scope>test</scope>
</dependency>
```

---

## Completion Checklist

### Phase 1: RBAC Enforcement
- [ ] Enable @EnableMethodSecurity
- [ ] Create AuthorizationService
- [ ] Add @PreAuthorize to UserController
- [ ] Add @PreAuthorize to TenantController
- [ ] Add @PreAuthorize to RoleController
- [ ] Add @PreAuthorize to BiometricController
- [ ] Add @PreAuthorize to StatisticsController
- [ ] Add @PreAuthorize to AuditLogController
- [ ] Update CustomUserDetailsService

### Phase 2: Multi-Tenancy
- [ ] Implement TenantContextFilter
- [ ] Implement TenantFilterAspect
- [ ] Verify @Filter on all entities
- [ ] Write tenant isolation tests

### Phase 3: Biometric Integration
- [ ] Complete BiometricServiceAdapter
- [ ] Add Resilience4j configuration
- [ ] Implement circuit breaker and retry
- [ ] Test integration with Biometric Processor

### Phase 4: Audit Logging
- [ ] Create AuditLogEntity
- [ ] Implement AuditLogAdapter (persist to DB)
- [ ] Create AuditLoggingAspect
- [ ] Apply @Audited to all services
- [ ] Create AuditLogController

### Phase 5: User Settings
- [ ] Create UserSettingsEntity
- [ ] Add V10 migration
- [ ] Implement UserSettingsService
- [ ] Implement ChangePasswordService
- [ ] Create SettingsController

### Phase 6: Email Integration
- [ ] Configure mail sender
- [ ] Create email templates
- [ ] Implement EmailServiceAdapter
- [ ] Implement PasswordResetService

### Phase 7: Rate Limiting
- [ ] Implement RateLimitingFilter
- [ ] Create RedisRateLimitService
- [ ] Configure rate limits per endpoint

### Phase 8: Integration Tests
- [ ] Setup TestContainers
- [ ] Write AuthenticationIntegrationTest
- [ ] Write RBACIntegrationTest
- [ ] Write MultiTenancyIntegrationTest
- [ ] Achieve 80%+ code coverage

---

## Estimated Timeline

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: RBAC | 3 days | None |
| Phase 2: Multi-Tenancy | 2 days | Phase 1 |
| Phase 3: Biometric | 3 days | Biometric Processor |
| Phase 4: Audit Logging | 3 days | Phase 1-2 |
| Phase 5: User Settings | 3 days | None |
| Phase 6: Email | 2 days | SMTP server |
| Phase 7: Rate Limiting | 2 days | Redis |
| Phase 8: Integration Tests | 5 days | Phases 1-7 |
| **Total** | **23 days** | |
