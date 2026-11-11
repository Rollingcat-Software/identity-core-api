package com.fivucsas.identity.application.service.devbench;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.input.SubmitDevbenchRunUseCase;
import com.fivucsas.identity.application.port.output.DevbenchRunStorePort;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DevbenchRunServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-10T21:30:00Z");
    private static final Instant START_OF_DAY = Instant.parse("2026-11-10T00:00:00Z");

    private final ObjectMapper mapper = new ObjectMapper();
    private final DevbenchRunStorePort store = mock(DevbenchRunStorePort.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    private DevbenchRunService service(boolean enabled, long cap) {
        return new DevbenchRunService(store, mapper, clock, enabled, cap);
    }

    private static byte[] body() {
        return DevbenchRunSanitizerTest.run(",\"participant\":\"Ayse\"").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void submit_WhenValidAndUnderCap_ShouldStoreSanitisedRun() {
        when(store.countReceivedSince(START_OF_DAY)).thenReturn(10L);

        SubmitDevbenchRunUseCase.Result result = service(true, 5000).submit(body());

        assertThat(result).isInstanceOf(SubmitDevbenchRunUseCase.Stored.class);
        ArgumentCaptor<DevbenchRunStorePort.NewRun> saved = ArgumentCaptor.forClass(DevbenchRunStorePort.NewRun.class);
        verify(store).save(saved.capture());
        assertThat(saved.getValue().receivedAt()).isEqualTo(NOW);
        assertThat(saved.getValue().batchId()).isEqualTo("20261110abcd");
        assertThat(saved.getValue().id()).isEqualTo(((SubmitDevbenchRunUseCase.Stored) result).id());
    }

    @Test
    void submit_WhenDailyCapReached_ShouldNotStore() {
        when(store.countReceivedSince(START_OF_DAY)).thenReturn(5000L);

        assertThat(service(true, 5000).submit(body())).isInstanceOf(SubmitDevbenchRunUseCase.OverDailyCap.class);
        verify(store, never()).save(any());
    }

    @Test
    void submit_WhenDisabled_ShouldNotTouchStore() {
        assertThat(service(false, 5000).submit(body())).isInstanceOf(SubmitDevbenchRunUseCase.Disabled.class);
        verify(store, never()).countReceivedSince(any());
        verify(store, never()).save(any());
    }

    @Test
    void submit_WhenInvalid_ShouldRejectWithReasonAndNotStore() {
        SubmitDevbenchRunUseCase.Result result = service(true, 5000).submit("[]".getBytes(StandardCharsets.UTF_8));

        assertThat(result).isEqualTo(new SubmitDevbenchRunUseCase.Rejected("not_an_object"));
        verify(store, never()).save(any());
    }

    @Test
    void exportJson_WhenRunsStored_ShouldAddIdAndReceivedAtToEachDocument() throws Exception {
        UUID id = UUID.randomUUID();
        when(store.findAllOldestFirst(DevbenchRunService.EXPORT_LIMIT)).thenReturn(List.of(
                new DevbenchRunStorePort.StoredRun(id, NOW, "{\"tool\":\"fivucsas devbench app v1\",\"runIndex\":1}")));

        JsonNode out = mapper.readTree(service(true, 5000).exportJson());

        assertThat(out.isArray()).isTrue();
        assertThat(out.get(0).path("id").asText()).isEqualTo(id.toString());
        assertThat(out.get(0).path("receivedAt").asText()).isEqualTo(NOW.toString());
        assertThat(out.get(0).path("runIndex").asInt()).isEqualTo(1);
    }

    @Test
    void exportCsv_WhenRunsStored_ShouldHaveHeaderAndOneRowPerRun() {
        when(store.findAllOldestFirst(DevbenchRunService.EXPORT_LIMIT)).thenReturn(List.of(
                new DevbenchRunStorePort.StoredRun(UUID.randomUUID(), NOW, "{\"runIndex\":1}"),
                new DevbenchRunStorePort.StoredRun(UUID.randomUUID(), NOW, "{\"runIndex\":2}")));

        String csv = service(true, 5000).exportCsv();

        assertThat(csv.split("\n")).hasSize(3);
    }
}
