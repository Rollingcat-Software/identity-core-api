package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a user attempts to register an additional device but
 * already has the maximum allowed active devices.
 *
 * <p>INVESTIGATION_MASTER_2026-05-07 §"user constraints":
 * "device count per user unbounded → bloated WebAuthn allowList".
 *
 * <p>Maps to HTTP 409 in {@code GlobalExceptionHandler} and surfaces the
 * cap so the frontend can prompt the user to remove a device.
 */
public class DeviceLimitExceededException extends DomainException {

    private static final String ERROR_CODE = "DEVICE_LIMIT_EXCEEDED";

    private final int maxDevices;
    private final int currentDevices;

    public DeviceLimitExceededException(int currentDevices, int maxDevices) {
        super(String.format(
                "User has %d active devices; max allowed is %d. Please remove an existing device before registering a new one.",
                currentDevices, maxDevices),
              ERROR_CODE);
        this.maxDevices = maxDevices;
        this.currentDevices = currentDevices;
    }

    public int getMaxDevices() {
        return maxDevices;
    }

    public int getCurrentDevices() {
        return currentDevices;
    }
}
