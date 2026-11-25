package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.AuthorTrialUseCase;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialAccessGuard;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("AuthorTrialController — access key gate and export headers")
class AuthorTrialControllerTest {

    private static final UUID TENANT = UUID.fromString("aaaaaaaa-1111-2222-3333-444444444444");
    private static final String KEY = "shared-secret";

    private AuthorTrialUseCase useCase;
    private AuthorTrialProperties properties;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        useCase = mock(AuthorTrialUseCase.class);
        properties = new AuthorTrialProperties();
        properties.setEnabled(true);
        properties.setAccessCode(KEY);
        properties.setTenantIds(List.of(TENANT.toString()));
        AuthorTrialController controller = new AuthorTrialController(
                useCase, new AuthorTrialAccessGuard(properties));
        mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new AuthorTrialExceptionHandler())
                .setMessageConverters(
                        new org.springframework.http.converter.StringHttpMessageConverter(),
                        new org.springframework.http.converter.json.MappingJackson2HttpMessageConverter(
                                new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()))
                .build();
    }

    @Test
    void disabledSurface_AnswersNotFound() throws Exception {
        properties.setEnabled(false);
        mvc.perform(get("/api/v1/author-trial/participants").header(AuthorTrialController.KEY_HEADER, KEY))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("AUTHOR_TRIAL_DISABLED"));
    }

    @Test
    void wrongKey_AnswersUnauthorized() throws Exception {
        mvc.perform(get("/api/v1/author-trial/participants").header(AuthorTrialController.KEY_HEADER, "nope"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("TRIAL_KEY_INVALID"));
        mvc.perform(get("/api/v1/author-trial/participants"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void participants_WithTheKey_ReturnsTheView() throws Exception {
        when(useCase.participants()).thenReturn(new AuthorTrialUseCase.ParticipantsView(
                TENANT, List.of(new AuthorTrialUseCase.ParticipantView("P1", true)),
                new AuthorTrialUseCase.FlowView("PUZZLE", true, "easy", 1, List.of("blink"))));

        mvc.perform(get("/api/v1/author-trial/participants").header(AuthorTrialController.KEY_HEADER, KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(TENANT.toString()))
                .andExpect(jsonPath("$.participants[0].code").value("P1"))
                .andExpect(jsonPath("$.flow.method").value("PUZZLE"));
    }

    @Test
    void export_SetsCsvHeadersAndNoStore() throws Exception {
        when(useCase.export("csv")).thenReturn(new AuthorTrialUseCase.ExportView(
                "date,participant\n2026-11-24,P1\n", "text/csv; charset=utf-8",
                "author_trial_sessions.csv"));

        mvc.perform(get("/api/v1/author-trial/export")
                        .param("format", "csv")
                        .header(AuthorTrialController.KEY_HEADER, KEY))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andExpect(header().string("Content-Disposition",
                        "attachment; filename=\"author_trial_sessions.csv\""))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void malformedBody_AnswersBadRequest() throws Exception {
        mvc.perform(post("/api/v1/author-trial/session")
                        .header(AuthorTrialController.KEY_HEADER, KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("TRIAL_BAD_REQUEST"));
    }

    @Test
    void malformedAttemptId_AnswersBadRequest() throws Exception {
        mvc.perform(post("/api/v1/author-trial/attempts/not-a-uuid/finish")
                        .header(AuthorTrialController.KEY_HEADER, KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void session_WithTheKey_DelegatesToTheUseCase() throws Exception {
        when(useCase.startSession(any(), any(), any())).thenReturn(
                new AuthorTrialUseCase.SessionView(UUID.randomUUID(), "token", "P1", "P1",
                        "genuine", 1, 1, "blink", true, "easy", 1,
                        new AuthorTrialUseCase.PuzzleConfigView(List.of("blink"), 1, "easy", true)));

        mvc.perform(post("/api/v1/author-trial/session")
                        .header(AuthorTrialController.KEY_HEADER, KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"participantCode\":\"P1\",\"mode\":\"genuine\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaSessionToken").value("token"));
    }
}