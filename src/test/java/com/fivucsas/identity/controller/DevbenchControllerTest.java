package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ExportDevbenchRunsUseCase;
import com.fivucsas.identity.application.port.input.SubmitDevbenchRunUseCase;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.service.devbench.DevbenchRunSanitizer;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayInputStream;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = DevbenchController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
class DevbenchControllerTest {

    @Autowired private MockMvc mockMvc;

    @MockBean private SubmitDevbenchRunUseCase submitUseCase;
    @MockBean private ExportDevbenchRunsUseCase exportUseCase;

    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;
    @MockBean private OtpService otpService;
    @MockBean private EmailService emailService;
    @MockBean private SmsService smsService;

    @Test
    void submit_WhenStored_ShouldReturn201WithIdOnly() throws Exception {
        UUID id = UUID.randomUUID();
        when(submitUseCase.submit(any())).thenReturn(new SubmitDevbenchRunUseCase.Stored(id));

        mockMvc.perform(post("/api/v1/devbench/runs").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    void submit_WhenRejected_ShouldReturn400WithReason() throws Exception {
        when(submitUseCase.submit(any())).thenReturn(new SubmitDevbenchRunUseCase.Rejected("unknown_tool"));

        mockMvc.perform(post("/api/v1/devbench/runs").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unknown_tool"));
    }

    @Test
    void submit_WhenOverDailyCap_ShouldReturn429WithRetryAfter() throws Exception {
        when(submitUseCase.submit(any())).thenReturn(new SubmitDevbenchRunUseCase.OverDailyCap());

        mockMvc.perform(post("/api/v1/devbench/runs").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    void submit_WhenDisabled_ShouldReturn503() throws Exception {
        when(submitUseCase.submit(any())).thenReturn(new SubmitDevbenchRunUseCase.Disabled());

        mockMvc.perform(post("/api/v1/devbench/runs").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void submit_WhenBodyOverLimit_ShouldReturn413WithoutCallingUseCase() throws Exception {
        String big = "{\"x\":\"" + "a".repeat(DevbenchRunSanitizer.MAX_BODY_BYTES) + "\"}";

        mockMvc.perform(post("/api/v1/devbench/runs").contentType(MediaType.APPLICATION_JSON).content(big))
                .andExpect(status().isPayloadTooLarge());
        verify(submitUseCase, never()).submit(any());
    }

    @Test
    void submit_WhenNotJsonContentType_ShouldReturn415() throws Exception {
        mockMvc.perform(post("/api/v1/devbench/runs").contentType(MediaType.TEXT_PLAIN).content("{}"))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    void export_WhenCsv_ShouldReturnCsvAttachment() throws Exception {
        when(exportUseCase.exportCsv()).thenReturn("id,receivedAt\n");

        mockMvc.perform(get("/api/v1/admin/devbench/runs").param("format", "csv"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"devbench_runs.csv\""))
                .andExpect(content().string("id,receivedAt\n"));
    }

    @Test
    void export_ShouldBeGuardedByRootOnly() throws Exception {
        PreAuthorize ann = DevbenchController.class.getMethod("export", String.class).getAnnotation(PreAuthorize.class);
        assertThat(ann).isNotNull();
        assertThat(ann.value()).isEqualTo("@rbac.isRoot()");
    }

    @Test
    void readBounded_WhenStreamLongerThanMax_ShouldReturnNull() throws Exception {
        assertThat(DevbenchController.readBounded(new ByteArrayInputStream(new byte[11]), 10)).isNull();
        assertThat(DevbenchController.readBounded(new ByteArrayInputStream(new byte[10]), 10)).hasSize(10);
    }
}
