package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationDocument;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient;
import com.fivucsas.identity.repository.VerificationDocumentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles DATA_EXTRACT verification step.
 * Delegates to biometric-processor for OCR/data extraction from document image,
 * then stores the extracted data in the verification_documents table.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataExtractHandler implements VerificationStepHandler {

    private final BiometricProcessorClient processorClient;
    private final VerificationDocumentRepository documentRepository;

    @Override
    public String getStepType() {
        return "DATA_EXTRACT";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String image = (String) data.get("image");
        if (image == null || image.isBlank()) {
            return VerificationStepResult.failure("Document image is required for data extraction");
        }

        try {
            Map<String, Object> response = processorClient.dataExtract(image);

            if (Boolean.FALSE.equals(response.get("success"))) {
                String error = (String) response.getOrDefault("error", "Data extraction failed");
                return VerificationStepResult.failure(error);
            }

            // Biometric-processor returns: document_type, extracted_data{name, surname, id_number, ...}, confidence, method
            // The personal data fields are nested inside "extracted_data"
            @SuppressWarnings("unchecked")
            Map<String, Object> extractedData = response.get("extracted_data") instanceof Map
                    ? (Map<String, Object>) response.get("extracted_data")
                    : response;

            String holderName = (String) extractedData.getOrDefault("name",
                    extractedData.getOrDefault("holder_name", ""));
            String documentNumber = (String) extractedData.getOrDefault("id_number",
                    extractedData.getOrDefault("document_number", ""));
            String documentType = (String) response.getOrDefault("document_type", "ID_CARD");
            String nationality = (String) extractedData.getOrDefault("nationality", "");
            String dobStr = (String) extractedData.getOrDefault("date_of_birth", "");
            String expiryStr = (String) extractedData.getOrDefault("expiry_date", "");

            // Store extracted data as VerificationDocument
            VerificationDocument.VerificationDocumentBuilder docBuilder = VerificationDocument.builder()
                    .session(session)
                    .user(session.getUser())
                    .documentType(documentType)
                    .documentNumber(documentNumber)
                    .holderName(holderName)
                    .nationality(nationality);

            if (!dobStr.isBlank()) {
                try {
                    docBuilder.dateOfBirth(LocalDate.parse(dobStr));
                } catch (DateTimeParseException e) {
                    log.warn("Could not parse date_of_birth '{}' for session {}", dobStr, session.getId());
                }
            }
            if (!expiryStr.isBlank()) {
                try {
                    docBuilder.expiryDate(LocalDate.parse(expiryStr));
                } catch (DateTimeParseException e) {
                    log.warn("Could not parse expiry_date '{}' for session {}", expiryStr, session.getId());
                }
            }

            VerificationDocument saved = documentRepository.save(docBuilder.build());

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("document_id", saved.getId().toString());
            resultData.put("holder_name", holderName);
            resultData.put("document_number", documentNumber);
            resultData.put("document_type", documentType);
            resultData.put("nationality", nationality);
            resultData.put("date_of_birth", dobStr);
            resultData.put("expiry_date", expiryStr);

            log.info("Data extraction completed for session {}: doc_id={}", session.getId(), saved.getId());
            return VerificationStepResult.success(resultData);
        } catch (Exception e) {
            log.error("Data extraction error for session {}: {}", session.getId(), e.getMessage(), e);
            return VerificationStepResult.failure("Data extraction service unavailable");
        }
    }
}
