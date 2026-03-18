package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.repository.NfcCardRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class NfcDocumentAuthHandler implements AuthMethodHandler {

    private final NfcCardRepository nfcCardRepository;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.NFC_DOCUMENT;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String cardSerial = (String) data.get("nfcData");

        if (cardSerial == null || cardSerial.isBlank()) {
            return StepResult.failure(
                    "NFC card serial is required. " +
                    "Tap your enrolled NFC card on the device reader.");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before NFC document verification");
        }

        // Look up the card by serial number (only active cards)
        Optional<NfcCard> cardOpt = nfcCardRepository.findByCardSerialAndIsActiveTrue(cardSerial);

        if (cardOpt.isEmpty()) {
            log.warn("NFC card not found or inactive: serial={} session={}", cardSerial, session.getId());
            return StepResult.failure("NFC card is not enrolled or has been deactivated");
        }

        NfcCard card = cardOpt.get();

        // Verify the card belongs to the session user
        if (!card.getUser().getId().equals(session.getUser().getId())) {
            log.warn("NFC card user mismatch: cardUser={} sessionUser={} session={}",
                    card.getUser().getId(), session.getUser().getId(), session.getId());
            return StepResult.failure("NFC card does not belong to this user");
        }

        // Mark the card as used
        card.markUsed();
        nfcCardRepository.save(card);

        log.info("NFC document authentication successful: serial={} user={} session={}",
                cardSerial, session.getUser().getId(), session.getId());
        return StepResult.success(Map.of(
                "verified", "true",
                "cardType", card.getCardType()
        ));
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("nfcData");
    }
}
