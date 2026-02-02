package com.fivucsas.identity.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for extending a guest's access duration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtendGuestAccessRequest {

    @NotNull(message = "Additional hours is required")
    @Min(value = 1, message = "Must extend by at least 1 hour")
    private Integer additionalHours;
}
