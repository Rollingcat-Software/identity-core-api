package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.AuthFlowStepRepository;
import com.fivucsas.identity.repository.AuthMethodRepository;
import com.fivucsas.identity.repository.TenantAuthMethodRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ManageAuthFlowServiceTest {

    @Mock private AuthFlowRepository authFlowRepository;
    @Mock private AuthFlowStepRepository authFlowStepRepository;
    @Mock private AuthMethodRepository authMethodRepository;
    @Mock private TenantRepository tenantRepository;
    @Mock private TenantAuthMethodRepository tenantAuthMethodRepository;

    @InjectMocks
    private ManageAuthFlowService service;

    @Test
    void createFlow_WhenAppLoginWithoutPasswordFirst_ShouldThrow() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.save(any())).thenReturn(AuthFlow.builder()
                .tenant(tenant).name("test").operationType(OperationType.APP_LOGIN).build());

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "FACE", 1, true, 120, 3, null, false, null
                )
        );
        var command = new CreateAuthFlowCommand("Test Flow", "desc", OperationType.APP_LOGIN, false, steps);

        assertThatThrownBy(() -> service.createFlow(tenantId, command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PASSWORD as the first step");
    }

    @Test
    void createFlow_WhenAppLoginWithPasswordFirst_ShouldSucceed() {
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod passwordMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.PASSWORD)).thenReturn(Optional.of(passwordMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "PASSWORD", 1, true, 120, 3, null, false, null
                )
        );
        var command = new CreateAuthFlowCommand("Login Flow", "desc", OperationType.APP_LOGIN, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_WhenDoorAccessWithoutPassword_ShouldSucceed() {
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod faceMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.FACE)).thenReturn(Optional.of(faceMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "FACE", 1, true, 120, 3, null, false, null
                )
        );
        var command = new CreateAuthFlowCommand("Door Flow", "desc", OperationType.DOOR_ACCESS, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_WhenApiAccessWithoutPasswordFirst_ShouldThrow() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.save(any())).thenReturn(AuthFlow.builder()
                .tenant(tenant).name("test").operationType(OperationType.API_ACCESS).build());

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "TOTP", 1, true, 120, 3, null, false, null
                )
        );
        var command = new CreateAuthFlowCommand("API Flow", "desc", OperationType.API_ACCESS, false, steps);

        assertThatThrownBy(() -> service.createFlow(tenantId, command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PASSWORD as the first step");
    }
}
