package com.fivucsas.identity.service;

import com.fivucsas.identity.domain.exception.BiometricEnrollmentException;
import com.fivucsas.identity.domain.exception.BiometricNotEnrolledException;
import com.fivucsas.identity.domain.exception.BiometricVerificationException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.dto.BiometricVerificationResponse;
import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.BiometricDataRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class BiometricService {

    private final BiometricDataRepository biometricDataRepository;
    private final com.fivucsas.identity.domain.repository.UserRepository userRepository;
    private final WebClient.Builder webClientBuilder;

    @Value("${biometric.service.url}")
    private String biometricServiceUrl;

    @Transactional
    public BiometricVerificationResponse enrollFace(UUID userId, MultipartFile image) {
        log.info("Enrolling face for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        // Call FastAPI to extract embedding
        Map<String, Object> response = callFastApiEnroll(image);

        if (!(Boolean) response.get("success")) {
            throw new BiometricEnrollmentException("Face enrollment failed: " + response.get("message"));
        }

        String embedding = (String) response.get("embedding");

        // Delete old biometric data if exists
        biometricDataRepository.findByUser(user).ifPresent(biometricDataRepository::delete);

        // Save new biometric data
        BiometricData biometricData = BiometricData.builder()
                .user(user)
                .embedding(embedding)
                .build();

        biometricDataRepository.save(biometricData);

        // Update user
        user.setBiometricEnrolled(true);
        user.setEnrolledAt(Instant.now());
        userRepository.save(user);

        log.info("Face enrolled successfully for user: {}", userId);

        return BiometricVerificationResponse.builder()
                .verified(true)
                .confidence(1.0)
                .message("Face enrolled successfully")
                .build();
    }

    public BiometricVerificationResponse verifyFace(UUID userId, MultipartFile image) {
        log.info("Verifying face for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        if (!user.isBiometricEnrolled()) {
            throw new BiometricNotEnrolledException(userId.toString());
        }

        BiometricData biometricData = biometricDataRepository.findByUser(user)
                .orElseThrow(() -> new BiometricNotEnrolledException(userId.toString()));

        // Call FastAPI to verify
        Map<String, Object> response = callFastApiVerify(image, biometricData.getEmbedding());

        boolean verified = (Boolean) response.get("verified");
        double confidence = ((Number) response.get("confidence")).doubleValue();
        String message = (String) response.get("message");

        // Update verification count if successful
        if (verified) {
            user.incrementVerificationCount();
            userRepository.save(user);
        }

        log.info("Face verification result for user {}: verified={}, confidence={}",
                userId, verified, confidence);

        return BiometricVerificationResponse.builder()
                .verified(verified)
                .confidence(confidence)
                .message(message)
                .build();
    }

    private Map<String, Object> callFastApiEnroll(MultipartFile image) {
        try {
            WebClient webClient = webClientBuilder.baseUrl(biometricServiceUrl).build();

            MultipartBodyBuilder builder = new MultipartBodyBuilder();
            builder.part("file", image.getResource());

            return webClient.post()
                    .uri("/api/v1/face/enroll")
                    .contentType(MediaType.MULTIPART_FORM_DATA)
                    .body(BodyInserters.fromMultipartData(builder.build()))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

        } catch (Exception e) {
            log.error("Error calling FastAPI enroll endpoint", e);
            throw new BiometricEnrollmentException("Failed to communicate with biometric service: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> callFastApiVerify(MultipartFile image, String storedEmbedding) {
        try {
            WebClient webClient = webClientBuilder.baseUrl(biometricServiceUrl).build();

            MultipartBodyBuilder builder = new MultipartBodyBuilder();
            builder.part("file", image.getResource());
            builder.part("stored_embedding", storedEmbedding);

            return webClient.post()
                    .uri("/api/v1/face/verify")
                    .contentType(MediaType.MULTIPART_FORM_DATA)
                    .body(BodyInserters.fromMultipartData(builder.build()))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

        } catch (Exception e) {
            log.error("Error calling FastAPI verify endpoint", e);
            throw new BiometricVerificationException("Failed to communicate with biometric service: " + e.getMessage(), e);
        }
    }
}
