package com.fivucsas.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.UUID;

/**
 * Row of {@code devbench_runs} (V89): one anonymous device benchmark run.
 *
 * <p>Deliberately NOT tenant-filtered: public research data with no tenant or user.
 * {@link Persistable} with {@code isNew() == true} because the id is assigned by the
 * caller (otherwise Hibernate treats the row as detached and merges, as RefreshToken once did).
 */
@Entity
@Table(name = "devbench_runs")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class DevbenchRunEntity implements Persistable<UUID> {

    @Id
    private UUID id;

    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;

    @Column(name = "tool", nullable = false, length = 80)
    private String tool;

    @Column(name = "batch_id", nullable = false, length = 64)
    private String batchId;

    @Column(name = "run_index", nullable = false)
    private short runIndex;

    @Column(name = "device_key", length = 120)
    private String deviceKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", nullable = false, columnDefinition = "jsonb")
    private String payload;

    @Override
    public boolean isNew() {
        return true;
    }
}
