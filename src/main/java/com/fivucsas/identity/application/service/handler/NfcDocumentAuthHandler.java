package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.NfcSerial;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.service.nfc.NfcChipAuthenticityVerdict;
import com.fivucsas.identity.entity.NfcCard;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class NfcDocumentAuthHandler implements AuthMethodHandler {

    private final NfcCardRepositoryPort nfcCardRepository;
    private final BiometricServicePort biometricServicePort;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.NFC_DOCUMENT;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String rawCardSerial = (String) data.get("nfcData");

        if (rawCardSerial == null || rawCardSerial.isBlank()) {
            return StepResult.failure(
                    "NFC card serial is required. " +
                    "Tap your enrolled NFC card on the device reader.");
        }

        // Canonicalize the serial to the same UPPERHEX form used at enroll so a
        // card enrolled from one client (e.g. mobile UPPERHEX) matches when
        // verified from another (e.g. web lowercase:colons).
        String cardSerial = NfcSerial.canonicalize(rawCardSerial);

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before NFC document verification");
        }

        // WS2 trust gate: if the client supplied the chip's EF.SOD (+ DGs), the
        // physical chip's authenticity is verified server-side via passive
        // authentication BEFORE the serial is accepted — a cloned/emulated card
        // presenting a known serial is rejected. Fail-closed. When no SOD is
        // present (serial-only legacy tap), behaviour is unchanged.
        String sod = trimToNull(data.get("sod"));
        if (sod == null) {
            sod = trimToNull(data.get("sod_b64"));
        }
        if (sod != null) {
            NfcChipAuthenticityVerdict verdict = NfcChipAuthenticityVerdict.from(
                    biometricServicePort.verifyNfcChipAuthenticity(sod, extractDataGroups(data)));
            if (!verdict.isAuthentic()) {
                log.warn("NFC document step rejected — chip not authentic: code={} reason={} session={}",
                        verdict.reasonCode(), verdict.reason(), session.getId());
                return StepResult.failure(
                        "NFC chip could not be authenticated"
                        + (verdict.reason() != null ? ": " + verdict.reason() : "."));
            }
        }

        // Look up the card by serial number, user ID, and active status
        Optional<NfcCard> cardOpt = nfcCardRepository.findByCardSerialAndUserIdAndIsActiveTrue(
                cardSerial, session.getUser().getId());

        if (cardOpt.isEmpty()) {
            log.warn("NFC card not found or inactive: serial={} userId={} session={}",
                    cardSerial, session.getUser().getId(), session.getId());
            return StepResult.failure("NFC card is not enrolled or has been deactivated");
        }

        NfcCard card = cardOpt.get();

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

    private static String trimToNull(Object o) {
        if (!(o instanceof String s)) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * Collects data-group base64 values from the step data. Accepts both numeric
     * keys ("1","2") and dg-prefixed keys ("dg1","dg2"); the adapter normalizes
     * to the bio-native numeric form.
     */
    private static Map<String, String> extractDataGroups(Map<String, Object> data) {
        Map<String, String> dgs = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : data.entrySet()) {
            String key = e.getKey() == null ? "" : e.getKey().toLowerCase(java.util.Locale.ROOT).trim();
            String value = trimToNull(e.getValue());
            if (value == null) {
                continue;
            }
            if (key.matches("dg\\d{1,2}")) {
                dgs.put(key, value);
            } else if (key.matches("\\d{1,2}")) {
                dgs.put("dg" + key, value);
            }
        }
        return dgs;
    }
}
