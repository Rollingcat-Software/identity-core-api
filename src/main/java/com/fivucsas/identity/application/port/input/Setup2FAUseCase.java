package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.TwoFactorSetupResponse;

/**
 * Input port for initiating 2FA setup.
 *
 * This interface defines the contract for starting 2FA setup process.
 */
public interface Setup2FAUseCase {

    /**
     * Initiates 2FA setup by generating secret and backup codes.
     *
     * @param query the query containing user email
     * @return setup response with secret and QR code URL
     */
    TwoFactorSetupResponse execute(GetUserByEmailQuery query);
}
