package com.fivucsas.identity.application.port.output;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Output port for the public device benchmark store ({@code devbench_runs}, V89).
 *
 * <p>Rows are anonymous research data: no tenant, no user, no IP.
 */
public interface DevbenchRunStorePort {

    /** A sanitised run ready to persist. {@code payloadJson} is a JSON object. */
    record NewRun(UUID id, Instant receivedAt, String tool, String batchId, int runIndex,
                  String deviceKey, String payloadJson) {}

    /** A stored run as read back for the admin export. */
    record StoredRun(UUID id, Instant receivedAt, String payloadJson) {}

    void save(NewRun run);

    long countReceivedSince(Instant since);

    /** Oldest first, at most {@code limit} rows. */
    List<StoredRun> findAllOldestFirst(int limit);
}
