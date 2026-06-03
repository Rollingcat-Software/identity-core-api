package com.fivucsas.identity.infrastructure.approvelogin;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.service.UsernamelessLoginFlowService;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the no-Firebase number-matching approve-login service.
 *
 * <p>Redis is mocked with an in-memory backing map so the full lifecycle
 * (create → pending list → decide → poll) can be exercised without a live
 * Redis. Covers allow/deny, wrong-number, expiry and non-owner paths.
 */
@ExtendWith(MockitoExtension.class)
class ApproveLoginServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private HashOperations<String, Object, Object> hashOps;
    @Mock private SetOperations<String, String> setOps;
    @Mock private TokenGenerationPort tokenGenerator;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private UserRepository userRepository;
    @Mock private UsernamelessLoginFlowService usernamelessLoginFlowService;

    private ApproveLoginService service;

    // In-memory stand-ins for the Redis hash + set backing stores.
    private final Map<String, Map<Object, Object>> hashStore = new HashMap<>();
    private final Map<String, Set<String>> setStore = new HashMap<>();

    private User user;
    private final UUID userId = UUID.randomUUID();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        service = new ApproveLoginService(redisTemplate, tokenGenerator, refreshTokenService,
                userRepository, usernamelessLoginFlowService);

        lenient().when(redisTemplate.opsForHash()).thenReturn((HashOperations) hashOps);
        lenient().when(redisTemplate.opsForSet()).thenReturn(setOps);

        // hash putAll / entries / put against the in-memory store
        lenient().doAnswer(inv -> {
            String key = inv.getArgument(0);
            Map<Object, Object> m = inv.getArgument(1);
            hashStore.computeIfAbsent(key, k -> new HashMap<>()).putAll(m);
            return null;
        }).when(hashOps).putAll(anyString(), any());
        lenient().doAnswer(inv -> {
            String key = inv.getArgument(0);
            hashStore.computeIfAbsent(key, k -> new HashMap<>()).put(inv.getArgument(1), inv.getArgument(2));
            return null;
        }).when(hashOps).put(anyString(), any(), any());
        lenient().when(hashOps.entries(anyString()))
                .thenAnswer(inv -> hashStore.getOrDefault(inv.getArgument(0), Map.of()));

        // set add / members / remove against the in-memory store
        lenient().doAnswer(inv -> {
            String key = inv.getArgument(0);
            Object[] vals = inv.getArguments();
            for (int i = 1; i < vals.length; i++) {
                setStore.computeIfAbsent(key, k -> new java.util.HashSet<>()).add((String) vals[i]);
            }
            return 1L;
        }).when(setOps).add(anyString(), any());
        lenient().when(setOps.members(anyString()))
                .thenAnswer(inv -> setStore.getOrDefault(inv.getArgument(0), Set.of()));
        lenient().doAnswer(inv -> {
            String key = inv.getArgument(0);
            Set<String> s = setStore.get(key);
            if (s != null) {
                s.remove(inv.getArgument(1));
            }
            return 1L;
        }).when(setOps).remove(anyString(), any());

        user = User.builder()
                .id(userId)
                .email("user@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("Approve")
                .lastName("Login")
                .status(UserStatus.ACTIVE)
                .build();
    }

    private String matchNumberFor(String sessionId) {
        return (String) hashStore.get("approve_login:session:" + sessionId).get("matchNumber");
    }

    @Nested
    @DisplayName("createSession")
    class CreateSession {

        @Test
        @DisplayName("returns PENDING with a two-digit match number for a known email")
        void createForKnownEmail() {
            when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

            Map<String, Object> res = service.createSession("user@example.com", "1.2.3.4", "agent");

            assertThat(res).containsEntry("status", "PENDING");
            assertThat(res.get("sessionId")).isNotNull();
            assertThat((String) res.get("matchNumber")).matches("\\d{2}");
            assertThat(res.get("expiresAtEpochSeconds")).isNotNull();
            // indexed for the resolved approver
            assertThat(setStore.get("approve_login:user:" + userId)).contains((String) res.get("sessionId"));
        }

        @Test
        @DisplayName("unknown email still returns PENDING (no existence oracle) but is not indexed")
        void createForUnknownEmailIsDecoy() {
            when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

            Map<String, Object> res = service.createSession("nobody@example.com", "1.2.3.4", "agent");

            assertThat(res).containsEntry("status", "PENDING");
            assertThat((String) res.get("matchNumber")).matches("\\d{2}");
            assertThat(setStore).isEmpty(); // no approver index for a decoy
        }
    }

    @Nested
    @DisplayName("decide")
    class Decide {

        private String startSession() {
            when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
            return (String) service.createSession("user@example.com", "1.2.3.4", "agent").get("sessionId");
        }

        @Test
        @DisplayName("allow + correct number mints tokens and flips poll to APPROVED")
        void allowMintsTokens() {
            String sessionId = startSession();
            String number = matchNumberFor(sessionId);

            // No Layer-2+ flow → the bridge mints tokens directly (expiresIn is
            // in millis; getSession divides by 1000 → 900L).
            when(usernamelessLoginFlowService.continueAfterLayer1(
                    eq(user), eq(AuthMethodType.APPROVE_LOGIN), eq("approve_login"),
                    eq("5.6.7.8"), eq("ua"), eq(null)))
                    .thenReturn(UsernamelessLoginFlowService.FlowOutcome
                            .minted("access-tok", "refresh-tok", 900_000L));

            Map<String, Object> decision = service.decide(sessionId, userId, "allow", number, "5.6.7.8", "ua");
            assertThat(decision).containsEntry("status", "APPROVED");

            Map<String, Object> poll = service.getSession(sessionId);
            assertThat(poll).containsEntry("status", "APPROVED");
            assertThat(poll).containsEntry("accessToken", "access-tok");
            assertThat(poll).containsEntry("refreshToken", "refresh-tok");
            assertThat(poll).containsEntry("expiresIn", 900L);
        }

        @Test
        @DisplayName("allow + Layer-2 flow returns MFA_PENDING instead of tokens")
        void allowWithFlowReturnsMfaPending() {
            String sessionId = startSession();
            String number = matchNumberFor(sessionId);

            when(usernamelessLoginFlowService.continueAfterLayer1(
                    eq(user), eq(AuthMethodType.APPROVE_LOGIN), eq("approve_login"),
                    eq("5.6.7.8"), eq("ua"), eq(null)))
                    .thenReturn(UsernamelessLoginFlowService.FlowOutcome
                            .pending("mfa-session-tok", 2, 2));

            Map<String, Object> decision = service.decide(sessionId, userId, "allow", number, "5.6.7.8", "ua");
            assertThat(decision).containsEntry("status", "APPROVED");

            Map<String, Object> poll = service.getSession(sessionId);
            assertThat(poll).containsEntry("status", "APPROVED");
            assertThat(poll).containsEntry("mfaRequired", true);
            assertThat(poll).containsEntry("mfaSessionToken", "mfa-session-tok");
            assertThat(poll).containsEntry("currentStep", 2);
            assertThat(poll).containsEntry("totalSteps", 2);
            assertThat(poll).doesNotContainKey("accessToken");
        }

        @Test
        @DisplayName("deny flips poll to DENIED and mints no tokens")
        void denyNoTokens() {
            String sessionId = startSession();

            Map<String, Object> decision = service.decide(sessionId, userId, "deny", null, "5.6.7.8", "ua");
            assertThat(decision).containsEntry("status", "DENIED");

            Map<String, Object> poll = service.getSession(sessionId);
            assertThat(poll).containsEntry("status", "DENIED");
            assertThat(poll).doesNotContainKey("accessToken");
        }

        @Test
        @DisplayName("allow with wrong number leaves session PENDING")
        void wrongNumberStaysPending() {
            String sessionId = startSession();
            String number = matchNumberFor(sessionId);
            String wrong = number.equals("00") ? "99" : "00";

            Map<String, Object> decision = service.decide(sessionId, userId, "allow", wrong, "5.6.7.8", "ua");
            assertThat(decision).containsEntry("status", "PENDING");
            assertThat(decision.get("message")).asString().contains("Match number");

            assertThat(service.getSession(sessionId)).containsEntry("status", "PENDING");
        }

        @Test
        @DisplayName("a different user cannot decide someone else's session")
        void nonOwnerCannotDecide() {
            String sessionId = startSession();
            String number = matchNumberFor(sessionId);

            Map<String, Object> decision = service.decide(sessionId, UUID.randomUUID(), "allow", number, "5.6.7.8", "ua");
            assertThat(decision).containsEntry("status", "PENDING");
            assertThat(decision.get("message")).asString().contains("Not authorized");
        }

        @Test
        @DisplayName("expired / unknown session reports EXPIRED")
        void expiredSession() {
            Map<String, Object> decision = service.decide(UUID.randomUUID().toString(), userId, "allow", "12", "5.6.7.8", "ua");
            assertThat(decision).containsEntry("status", "EXPIRED");
        }
    }

    @Nested
    @DisplayName("listPending / getSession")
    class ListAndPoll {

        @Test
        @DisplayName("listPending returns the approver's open requests")
        void listPendingReturnsOpenRequests() {
            when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
            String sessionId = (String) service.createSession("user@example.com", "1.2.3.4", "agent").get("sessionId");

            List<Map<String, Object>> pending = service.listPending(userId);
            assertThat(pending).hasSize(1);
            assertThat(pending.get(0)).containsEntry("sessionId", sessionId);
            assertThat(pending.get(0).get("matchNumber")).isEqualTo(matchNumberFor(sessionId));
            assertThat(pending.get(0)).containsEntry("initiatorIp", "1.2.3.4");
        }

        @Test
        @DisplayName("getSession on unknown id reports EXPIRED")
        void getUnknownSession() {
            assertThat(service.getSession("missing")).containsEntry("status", "EXPIRED");
        }
    }

    @Nested
    @DisplayName("matchNumber zero-pad-safe comparison (#21)")
    class MatchNumberComparison {

        @Test
        @DisplayName("exact equal strings match")
        void exactMatch() {
            assertThat(ApproveLoginService.matchNumbersEqual("07", "07")).isTrue();
            assertThat(ApproveLoginService.matchNumbersEqual("42", "42")).isTrue();
        }

        @Test
        @DisplayName("leading-zero dropped by a client still matches (07 == 7)")
        void leadingZeroNormalized() {
            assertThat(ApproveLoginService.matchNumbersEqual("07", "7")).isTrue();
            assertThat(ApproveLoginService.matchNumbersEqual("7", "07")).isTrue();
            assertThat(ApproveLoginService.matchNumbersEqual("00", "0")).isTrue();
        }

        @Test
        @DisplayName("whitespace is trimmed before comparing")
        void trimmed() {
            assertThat(ApproveLoginService.matchNumbersEqual("07", " 07 ")).isTrue();
        }

        @Test
        @DisplayName("genuinely different numbers do not match")
        void mismatch() {
            assertThat(ApproveLoginService.matchNumbersEqual("07", "08")).isFalse();
            assertThat(ApproveLoginService.matchNumbersEqual("12", "21")).isFalse();
        }

        @Test
        @DisplayName("null / blank inputs never match")
        void nullOrBlank() {
            assertThat(ApproveLoginService.matchNumbersEqual(null, "07")).isFalse();
            assertThat(ApproveLoginService.matchNumbersEqual("07", null)).isFalse();
            assertThat(ApproveLoginService.matchNumbersEqual("", "")).isFalse();
            assertThat(ApproveLoginService.matchNumbersEqual("07", "  ")).isFalse();
        }

        @Test
        @DisplayName("non-numeric strings only match when exactly equal")
        void nonNumeric() {
            assertThat(ApproveLoginService.matchNumbersEqual("ab", "ab")).isTrue();
            assertThat(ApproveLoginService.matchNumbersEqual("ab", "cd")).isFalse();
        }
    }
}
