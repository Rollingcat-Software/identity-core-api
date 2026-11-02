package com.fivucsas.identity.infrastructure.attestation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Cached view of Google's Android attestation certificate status list
 * ({@code https://android.googleapis.com/attestation/status}).
 *
 * <p>The list maps certificate serial numbers (lowercase hex, no leading zeros,
 * i.e. {@code BigInteger.toString(16)}) to a status; any entry with
 * {@code "status":"REVOKED"} (or {@code SUSPENDED}) marks that certificate as not
 * trustworthy. It is fetched lazily on first use, refreshed after {@code ttl}, and
 * a stale copy is used for up to {@code maxStale} when a refresh fails. Beyond that
 * {@link #revokedSerials()} returns empty and the caller applies its fail policy.
 */
@Slf4j
class GoogleAttestationStatusList {

    private final Supplier<String> fetcher;
    private final Duration ttl;
    private final Duration maxStale;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();

    private volatile Snapshot snapshot;

    private record Snapshot(Set<String> revoked, Instant fetchedAt) {
    }

    GoogleAttestationStatusList(Supplier<String> fetcher, Duration ttl, Duration maxStale, Clock clock) {
        this.fetcher = fetcher;
        this.ttl = ttl;
        this.maxStale = maxStale;
        this.clock = clock;
    }

    /** HTTP fetcher for the production list. */
    static Supplier<String> httpFetcher(String url, Duration timeout) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(timeout).build();
        return () -> {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(timeout)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new IllegalStateException("status list HTTP " + response.statusCode());
                }
                return response.body();
            } catch (IOException e) {
                throw new IllegalStateException("status list fetch failed: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("status list fetch interrupted", e);
            }
        };
    }

    /**
     * The revoked serials, or empty when no list fresh enough (within
     * {@code ttl + maxStale}) is available.
     */
    Optional<Set<String>> revokedSerials() {
        Instant now = clock.instant();
        Snapshot s = snapshot;
        if (s == null || s.fetchedAt().plus(ttl).isBefore(now)) {
            synchronized (this) {
                s = snapshot;
                if (s == null || s.fetchedAt().plus(ttl).isBefore(now)) {
                    try {
                        Set<String> revoked = parse(fetcher.get());
                        s = new Snapshot(revoked, now);
                        snapshot = s;
                        log.info("Android attestation status list refreshed: {} revoked/suspended entries",
                                revoked.size());
                    } catch (RuntimeException e) {
                        log.warn("Android attestation status list refresh failed: {}", e.getMessage());
                    }
                }
            }
        }
        if (s == null || s.fetchedAt().plus(ttl).plus(maxStale).isBefore(now)) {
            return Optional.empty();
        }
        return Optional.of(s.revoked());
    }

    Set<String> parse(String json) {
        try {
            JsonNode entries = mapper.readTree(json).get("entries");
            if (entries == null || !entries.isObject()) {
                throw new IllegalStateException("status list has no entries object");
            }
            Set<String> revoked = new HashSet<>();
            Iterator<Map.Entry<String, JsonNode>> it = entries.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                JsonNode status = e.getValue().get("status");
                String st = status == null ? "" : status.asText().toUpperCase(Locale.ROOT);
                if ("REVOKED".equals(st) || "SUSPENDED".equals(st)) {
                    revoked.add(normalizeSerial(e.getKey()));
                }
            }
            return Collections.unmodifiableSet(revoked);
        } catch (IOException e) {
            throw new IllegalStateException("status list is not valid JSON", e);
        }
    }

    /** Lowercase hex with leading zeros stripped (the list's key format). */
    static String normalizeSerial(String hex) {
        String s = hex.trim().toLowerCase(Locale.ROOT);
        int i = 0;
        while (i < s.length() - 1 && s.charAt(i) == '0') {
            i++;
        }
        return s.substring(i);
    }
}
