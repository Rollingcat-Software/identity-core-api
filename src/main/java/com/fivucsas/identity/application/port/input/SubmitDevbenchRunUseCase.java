package com.fivucsas.identity.application.port.input;

import java.util.UUID;

/** Public, anonymous intake of one device benchmark run. */
public interface SubmitDevbenchRunUseCase {

    /** Outcome of one submission; the controller maps each case to an HTTP status. */
    sealed interface Result permits Stored, Rejected, OverDailyCap, Disabled {}

    record Stored(UUID id) implements Result {}

    record Rejected(String reason) implements Result {}

    record OverDailyCap() implements Result {}

    record Disabled() implements Result {}

    Result submit(byte[] body);
}
