package com.fivucsas.identity.application.service.devbench;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fivucsas.identity.application.port.input.ExportDevbenchRunsUseCase;
import com.fivucsas.identity.application.port.input.SubmitDevbenchRunUseCase;
import com.fivucsas.identity.application.port.output.DevbenchRunStorePort;
import com.fivucsas.identity.application.port.output.DevbenchRunStorePort.StoredRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Public device benchmark intake and the ROOT export.
 *
 * <p>Abuse limits, outermost first: the per-IP cap in {@code RateLimitFilter}, the body
 * size and key allow-list in {@link DevbenchRunSanitizer}, and here a global cap on rows
 * accepted per UTC day, which holds even when an attacker rotates addresses.
 */
@Service
@Slf4j
public class DevbenchRunService implements SubmitDevbenchRunUseCase, ExportDevbenchRunsUseCase {

    /** Hard ceiling on one export; far above any realistic study size. */
    static final int EXPORT_LIMIT = 50_000;

    private final DevbenchRunStorePort store;
    private final DevbenchRunSanitizer sanitizer;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final boolean enabled;
    private final long dailyCap;

    @Autowired
    public DevbenchRunService(DevbenchRunStorePort store,
                              ObjectMapper mapper,
                              @Value("${app.devbench.enabled:true}") boolean enabled,
                              @Value("${app.devbench.daily-cap:5000}") long dailyCap) {
        this(store, mapper, Clock.systemUTC(), enabled, dailyCap);
    }

    DevbenchRunService(DevbenchRunStorePort store, ObjectMapper mapper, Clock clock,
                       boolean enabled, long dailyCap) {
        this.store = store;
        this.sanitizer = new DevbenchRunSanitizer(mapper);
        this.mapper = mapper;
        this.clock = clock;
        this.enabled = enabled;
        this.dailyCap = dailyCap;
    }

    @Override
    public Result submit(byte[] body) {
        if (!enabled) {
            return new Disabled();
        }
        DevbenchRunSanitizer.Outcome outcome = sanitizer.sanitize(body);
        if (outcome instanceof DevbenchRunSanitizer.Invalid invalid) {
            log.info("devbench run rejected: {}", invalid.reason());
            return new Rejected(invalid.reason());
        }
        DevbenchRunSanitizer.ValidRun run = ((DevbenchRunSanitizer.Valid) outcome).run();

        Instant now = clock.instant();
        Instant startOfDay = LocalDate.ofInstant(now, ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant();
        if (store.countReceivedSince(startOfDay) >= dailyCap) {
            log.warn("devbench daily cap {} reached; run dropped", dailyCap);
            return new OverDailyCap();
        }
        UUID id = UUID.randomUUID();
        store.save(new DevbenchRunStorePort.NewRun(id, now, run.tool(), run.batchId(), run.runIndex(),
                run.deviceKey(), run.payloadJson()));
        log.info("devbench run stored id={} batch={} run={}", id, run.batchId(), run.runIndex());
        return new Stored(id);
    }

    @Override
    public String exportJson() {
        ArrayNode out = mapper.createArrayNode();
        for (StoredRun r : store.findAllOldestFirst(EXPORT_LIMIT)) {
            ObjectNode doc = parse(r);
            ObjectNode withMeta = mapper.createObjectNode();
            withMeta.put("id", r.id().toString());
            withMeta.put("receivedAt", r.receivedAt().toString());
            withMeta.setAll(doc);
            out.add(withMeta);
        }
        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(out);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("devbench export serialisation failed", e);
        }
    }

    @Override
    public String exportCsv() {
        List<DevbenchCsv.Row> rows = new ArrayList<>();
        for (StoredRun r : store.findAllOldestFirst(EXPORT_LIMIT)) {
            rows.add(new DevbenchCsv.Row(r.id().toString(), r.receivedAt().toString(), parse(r)));
        }
        return DevbenchCsv.render(rows);
    }

    private ObjectNode parse(StoredRun r) {
        try {
            return (ObjectNode) mapper.readTree(r.payloadJson());
        } catch (JsonProcessingException | ClassCastException e) {
            throw new IllegalStateException("stored devbench run " + r.id() + " is not a JSON object", e);
        }
    }
}
