package com.fivucsas.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BiometricVerificationResponse {

    private boolean verified;
    private double confidence;
    private String message;

    /**
     * Cosine distance between query embedding and the matched enrolled
     * template, as returned by the biometric processor. Lower is better.
     * Null when the bio processor did not include the field (legacy /verify
     * before the contract was tightened, or a search miss with no candidate).
     *
     * <p>INVESTIGATION_MASTER_2026-05-07 wires §"Face-verify response missing
     * distance/threshold": frontend was synthesising
     * {@code distance=1, threshold=0.4} sentinels because the API never
     * surfaced the real values. Wiring them through here lets the SPA render
     * margin/score telemetry without lying to the user.</p>
     */
    private Double distance;

    /**
     * Decision threshold the bio processor compared {@code distance} against.
     * The bio service applies adaptive thresholds (e.g. aged-template
     * relaxations); echoing the actual threshold used for THIS verification
     * lets the UI show "passed by 0.04" / "missed by 0.02" deltas. Null if
     * the processor didn't include it.
     */
    private Double threshold;
}
