package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.VerificationDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface VerificationDocumentRepository extends JpaRepository<VerificationDocument, UUID> {

    List<VerificationDocument> findAllByUserId(UUID userId);

    List<VerificationDocument> findAllBySessionId(UUID sessionId);
}
