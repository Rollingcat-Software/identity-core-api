package com.fivucsas.identity.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * HS512 key registry that supports parallel-verify rotation.
 *
 * <p>One kid is the <i>active</i> signing key (used by {@link JwtService} when
 * minting new tokens); any number of additional <i>retired</i> kids stay in the
 * verification set so tokens minted before a rotation continue to verify until
 * they expire. Operators roll a new key with three steps:
 * <ol>
 *   <li>Mint the new HS512 secret offline; export it as
 *       {@code JWT_HS_KEY_<NEW_KID_UPPER_DASHES_TO_UNDERSCORES>}.</li>
 *   <li>Restart with the new env var present and {@code APP_SECURITY_JWT_RETIRED_HS_KIDS}
 *       containing the old kid. Tokens minted by either secret keep verifying.</li>
 *   <li>After soak (>= refresh-token max lifetime) flip
 *       {@code APP_SECURITY_JWT_ACTIVE_HS_KID} to the new kid. Old kid stays in
 *       retired list until a follow-up release drops it.</li>
 * </ol>
 *
 * <p>Backward compat: when the active kid's per-kid env var is missing the registry
 * falls back to the legacy {@code JWT_SECRET} via {@link JwtSecretProvider}. This
 * preserves existing single-key deploys (no env-var changes required to ship the
 * registry).
 *
 * @see <a href="ANALYSIS_2026-05-02_USER_DOMAIN_AND_JWT_ROTATION.md">Analysis 2026-05-02</a>
 */
@Component
@Slf4j
public class HsKeyRegistry {

    /** Default active kid — matches the historical {@code JwtService.HS_KID} value. */
    public static final String DEFAULT_ACTIVE_KID = "hs-2026-04";

    private final JwtSecretProvider jwtSecretProvider;
    private final Environment environment;

    @Value("${app.security.jwt.active-hs-kid:" + DEFAULT_ACTIVE_KID + "}")
    private String activeHsKid;

    @Value("${app.security.jwt.retired-hs-kids:}")
    private String retiredHsKidsCsv;

    private String resolvedActiveKid;
    private Map<String, SecretKey> keysByKid = Collections.emptyMap();

    public HsKeyRegistry(JwtSecretProvider jwtSecretProvider, Environment environment) {
        this.jwtSecretProvider = jwtSecretProvider;
        this.environment = environment;
    }

    @PostConstruct
    void initialize() {
        Map<String, SecretKey> registry = new LinkedHashMap<>();
        Set<String> kids = new TreeSet<>();

        String active = (activeHsKid == null || activeHsKid.isBlank())
                ? DEFAULT_ACTIVE_KID
                : activeHsKid.trim();
        kids.add(active);

        if (retiredHsKidsCsv != null && !retiredHsKidsCsv.isBlank()) {
            for (String raw : retiredHsKidsCsv.split(",")) {
                String kid = raw.trim();
                if (!kid.isEmpty()) {
                    kids.add(kid);
                }
            }
        }

        for (String kid : kids) {
            SecretKey key = loadKeyForKid(kid, kid.equals(active));
            if (key != null) {
                registry.put(kid, key);
            } else if (kid.equals(active)) {
                // Should be unreachable — loadKeyForKid returns the legacy
                // JWT_SECRET fallback for the active kid.
                throw new IllegalStateException(
                        "Active HS kid '" + kid + "' has no resolvable secret");
            } else {
                log.warn("HS key registry: retired kid '{}' has no env var "
                        + "(JWT_HS_KEY_{}). Skipping — tokens minted with this kid "
                        + "will be rejected.", kid, envSuffix(kid));
            }
        }

        this.resolvedActiveKid = active;
        this.keysByKid = Collections.unmodifiableMap(registry);

        log.info("HS key registry initialized: active-kid={} total-kids={} (retired={})",
                resolvedActiveKid, registry.size(), Math.max(0, registry.size() - 1));
    }

    /**
     * Returns the kid stamped on every newly-signed HS512 token.
     */
    public String getActiveKid() {
        return resolvedActiveKid;
    }

    /**
     * Returns the {@link SecretKey} used to <i>sign</i> new HS512 tokens.
     */
    public SecretKey getActiveKey() {
        SecretKey key = keysByKid.get(resolvedActiveKid);
        if (key == null) {
            throw new IllegalStateException(
                    "HS key registry has no key for active kid '" + resolvedActiveKid + "'");
        }
        return key;
    }

    /**
     * Looks up the verification key for a given kid. Returns {@code null} when the
     * kid is not registered (caller turns this into a {@code SignatureException}).
     */
    public SecretKey keyFor(String kid) {
        if (kid == null) {
            return null;
        }
        return keysByKid.get(kid);
    }

    /**
     * Set of all kids currently held in the registry (active + retired).
     * Exposed for diagnostics / tests.
     */
    public Set<String> allKids() {
        return Collections.unmodifiableSet(keysByKid.keySet());
    }

    /**
     * Resolve a {@link SecretKey} for {@code kid} from the environment. Lookup order:
     * <ol>
     *   <li>{@code JWT_HS_KEY_<KID_UPPER_DASHES_TO_UNDERSCORES>} (per-kid env var)</li>
     *   <li>{@code app.security.jwt.hs-key.<kid>} (Spring property fallback for tests)</li>
     *   <li>For the active kid only: legacy {@link JwtSecretProvider#getSecret()}
     *       (backward compat for single-key deploys).</li>
     * </ol>
     */
    private SecretKey loadKeyForKid(String kid, boolean isActive) {
        String envVar = "JWT_HS_KEY_" + envSuffix(kid);
        String secret = System.getenv(envVar);
        if (secret == null || secret.isBlank()) {
            // Spring property fallback — used by tests via MockEnvironment.
            secret = environment.getProperty("app.security.jwt.hs-key." + kid);
        }
        if ((secret == null || secret.isBlank()) && isActive) {
            // Backward compat: pre-registry deploys configured a single JWT_SECRET
            // and the active kid implicitly mapped to it. Keep that working.
            secret = jwtSecretProvider.getSecret();
            log.info("HS key registry: active kid '{}' resolved via legacy "
                    + "JWT_SECRET (backward-compat path)", kid);
        }
        if (secret == null || secret.isBlank()) {
            return null;
        }
        byte[] bytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(bytes);
    }

    private static String envSuffix(String kid) {
        return kid.toUpperCase(Locale.ROOT).replace('-', '_');
    }
}
