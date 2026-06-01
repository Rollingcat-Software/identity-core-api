package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.AccountLockedException;
import com.fivucsas.identity.domain.exception.AccountNotActiveException;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Single, path-independent gate for per-account login state: temporary lockout
 * (NIST 800-63B 5-strike) and administrative account status (ACTIVE vs
 * SUSPENDED / INACTIVE).
 *
 * <p><b>SECURITY (2026-06-01, LOGIC_AUDIT + staging verification).</b> Two bugs:
 * <ol>
 *   <li>The strike counter + status check used to live ONLY inside
 *       {@code AuthenticateUserService.execute} (the legacy password path); the
 *       identifier-first and the live config-driven {@code /auth/mfa/step} engine
 *       skipped them, so lockout was bypassable and suspended users could still
 *       authenticate.</li>
 *   <li>Even on the legacy path the lock NEVER PERSISTED: the increment was saved
 *       inside the {@code @Transactional} login method and then discarded when it
 *       threw {@code InvalidCredentialsException} — Spring rolled the whole
 *       transaction (including the counter save) back. Verified on staging: 6 wrong
 *       passwords left {@code failed_login_attempts = 0}.</li>
 * </ol>
 * This guard fixes both: the mutating operations run in their OWN committed
 * transaction ({@link Propagation#REQUIRES_NEW}) so they survive the caller's
 * rollback-on-throw, and every login entry point calls the same gate.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAccountStateGuard {

    /** NIST 800-63B online-guessing throttle. */
    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;

    /**
     * Rejects the login if the account is currently locked (an EXPIRED lock is
     * auto-cleared) or not ACTIVE. Read-only on the passed entity; the expiry
     * auto-clear is delegated to a committed helper. Call after the user is
     * resolved and before any factor is accepted.
     *
     * @throws AccountLockedException    (HTTP 423) while a lockout is in effect
     * @throws AccountNotActiveException (HTTP 403) when status != ACTIVE
     */
    public void enforceLoginAllowed(User user, String email, String ipAddress) {
        if (user.isLocked()) {
            Instant lockedUntil = user.getLockedUntil();
            if (lockedUntil != null && Instant.now().isAfter(lockedUntil)) {
                clearLock(user.getId()); // lock window elapsed → unlock and proceed
            } else {
                log.warn("AUDIT: Login failed — email={}, reason: account_locked, ip={}", email, ipAddress);
                auditLogPort.logAuthenticationFailed(email, ipAddress, "Account locked");
                long remaining = lockedUntil != null
                        ? Math.max(0L, Duration.between(Instant.now(), lockedUntil).getSeconds())
                        : 0L;
                throw new AccountLockedException(remaining);
            }
        }
        if (!user.isActive()) {
            String state = user.isSuspended() ? "SUSPENDED" : "INACTIVE";
            log.warn("AUDIT: Login refused — email={}, reason: account_not_active ({}), ip={}", email, state, ipAddress);
            auditLogPort.logAuthenticationFailed(email, ipAddress, "Account not active: " + state);
            throw new AccountNotActiveException();
        }
    }

    /**
     * Records a failed factor on the per-account strike counter and locks the
     * account at the threshold. Runs in its OWN committed transaction so the
     * increment/lock survives the caller throwing {@code InvalidCredentialsException}
     * (which rolls the caller's transaction back). Path-independent: every failed
     * factor on every login path calls this.
     *
     * @return true if THIS failure triggered the lockout
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean recordFailedAttempt(UUID userId, String email, String ipAddress) {
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return false;
        }
        user.incrementFailedLoginAttempts();
        boolean justLocked = false;
        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.lockAccount(LOCKOUT_DURATION);
            justLocked = true;
            log.warn("AUDIT: Account locked — email={}, failedAttempts={}, ip={}", email, MAX_FAILED_ATTEMPTS, ipAddress);
            auditLogPort.logAuthenticationFailed(email, ipAddress,
                    "Account locked after " + MAX_FAILED_ATTEMPTS + " failed attempts");
        } else {
            auditLogPort.logAuthenticationFailed(email, ipAddress,
                    "Invalid credential (attempt " + user.getFailedLoginAttempts() + "/" + MAX_FAILED_ATTEMPTS + ")");
        }
        userRepository.save(user);
        return justLocked;
    }

    /** Resets the strike counter after a successful factor (own committed tx). */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccess(UUID userId) {
        User user = userRepository.findById(userId).orElse(null);
        if (user != null && user.getFailedLoginAttempts() > 0) {
            user.resetFailedLoginAttempts();
            userRepository.save(user);
        }
    }

    /** Clears an expired lock (own committed tx). */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearLock(UUID userId) {
        User user = userRepository.findById(userId).orElse(null);
        if (user != null) {
            user.resetFailedLoginAttempts();
            userRepository.save(user);
            log.info("Account auto-unlocked after lockout period for user: {}", userId);
        }
    }
}
