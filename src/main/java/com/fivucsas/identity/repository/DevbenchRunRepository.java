package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.DevbenchRunEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface DevbenchRunRepository extends JpaRepository<DevbenchRunEntity, UUID> {

    long countByReceivedAtGreaterThanEqual(Instant since);

    List<DevbenchRunEntity> findAllByOrderByReceivedAtAsc(Pageable page);
}
