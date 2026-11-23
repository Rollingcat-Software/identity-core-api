package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.DevbenchRunStorePort;
import com.fivucsas.identity.entity.DevbenchRunEntity;
import com.fivucsas.identity.repository.DevbenchRunRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

/** JPA adapter for {@link DevbenchRunStorePort}. */
@Repository
@RequiredArgsConstructor
public class DevbenchRunStoreAdapter implements DevbenchRunStorePort {

    private final DevbenchRunRepository repository;

    @Override
    public void save(NewRun run) {
        repository.save(new DevbenchRunEntity(run.id(), run.receivedAt(), run.tool(), run.batchId(),
                (short) run.runIndex(), run.deviceKey(), run.payloadJson()));
    }

    @Override
    public long countReceivedSince(Instant since) {
        return repository.countByReceivedAtGreaterThanEqual(since);
    }

    @Override
    public List<StoredRun> findAllOldestFirst(int limit) {
        return repository.findAllByOrderByReceivedAtAsc(PageRequest.of(0, limit)).stream()
                .map(e -> new StoredRun(e.getId(), e.getReceivedAt(), e.getPayload()))
                .toList();
    }
}
