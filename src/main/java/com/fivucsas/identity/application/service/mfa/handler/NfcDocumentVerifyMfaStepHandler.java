package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.NfcSerial;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * MFA step handler for the {@code NFC_DOCUMENT} auth method.
 *
 * <p><b>S9 (security review) — fail-closed gate.</b> The presented
 * {@code nfcData} is a card <em>serial number</em>, which is readable and
 * cloneable from the document surface — it is NOT a secret. Matching it against
 * an enrolled active card therefore does not constitute real authentication;
 * anyone who learns the serial would pass the step. This was security theater of
 * the same class as the removed FINGERPRINT placeholder.
 *
 * <p>Until genuine on-chip authentication (ICAO 9303 passive authentication /
 * BAC/PACE active authentication, which proves possession of the physical
 * document via its protected chip) is implemented, serial-only NFC verification
 * must NOT satisfy an auth factor. This handler is therefore <b>fail-closed by
 * default</b>: {@link #verify(MfaSession, User, Map)} returns
 * {@link MfaStepResult#fail()} regardless of serial match.
 *
 * <p>The legacy serial-match behavior can be explicitly re-enabled (opt-in) via
 * {@code fivucsas.nfc.serial-only-auth-enabled=true}, for environments that have
 * accepted the documented risk. This is ENABLED in production (2026-06-01):
 * student/campus cards are plain MIFARE (UID/serial only, no ICAO chip), so chip
 * passive-authentication can never apply to them, and NFC is consumed here only
 * as one factor inside an MFA flow (never a sole high-assurance factor). The serial
 * is canonicalized to the same UPPERHEX form used at enrollment before lookup, so a
 * web tap matches a card enrolled from any client. Revert with no redeploy by
 * unsetting {@code FIVUCSAS_NFC_SERIAL_ONLY_AUTH_ENABLED} (kill-switch).
 */
@Component
@Slf4j
public class NfcDocumentVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final NfcCardRepositoryPort nfcCardRepository;

    /**
     * When {@code false} (default), serial-only NFC verification is fail-closed
     * pending real chip authentication. When {@code true}, the legacy
     * serial-match behavior is restored (explicit, documented-risk opt-in).
     */
    private final boolean serialOnlyAuthEnabled;

    public NfcDocumentVerifyMfaStepHandler(
            NfcCardRepositoryPort nfcCardRepository,
            @Value("${fivucsas.nfc.serial-only-auth-enabled:false}") boolean serialOnlyAuthEnabled) {
        this.nfcCardRepository = nfcCardRepository;
        this.serialOnlyAuthEnabled = serialOnlyAuthEnabled;
    }

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.NFC_DOCUMENT;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        if (!serialOnlyAuthEnabled) {
            // S9 fail-closed gate: a card serial is not a secret, so matching it
            // is not authentication. Refuse the factor until chip authentication
            // (ICAO passive auth) is implemented.
            log.warn("NFC_DOCUMENT serial-only auth is DISABLED (fivucsas.nfc.serial-only-auth-enabled=false); "
                    + "failing closed for user {} pending genuine chip authentication", user.getId());
            return MfaStepResult.fail();
        }

        // Legacy opt-in path (documented risk): serial match only.
        String nfcData = (String) data.get("nfcData");
        if (nfcData == null || nfcData.isBlank()) {
            return MfaStepResult.fail();
        }
        // Canonicalize to the same UPPERHEX, no-separators form used at enrollment
        // (ManageNfcCardService.enrollCard + NfcDocumentAuthHandler.validate) so a
        // web tap (lowercase-with-colons "04:a2:24:..") matches a card regardless of
        // the client it was enrolled from. Without this, web logins miss the stored
        // canonical serial ("04A224..") even though the card IS enrolled and active.
        String cardSerial = NfcSerial.canonicalize(nfcData);
        boolean ok = nfcCardRepository
                .findByCardSerialAndUserIdAndIsActiveTrue(cardSerial, user.getId())
                .isPresent();
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
