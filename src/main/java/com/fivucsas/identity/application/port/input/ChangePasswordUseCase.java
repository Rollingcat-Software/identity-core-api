package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.ChangePasswordCommand;

/**
 * Input port for changing a user's password.
 */
public interface ChangePasswordUseCase {

    void execute(ChangePasswordCommand command);
}
