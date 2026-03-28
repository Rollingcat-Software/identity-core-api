package com.fivucsas.identity.application.dto.response;

import java.util.List;

public record IndustryTemplateResponse(
    String templateId,
    String name,
    String description,
    List<String> steps
) {}
