package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.NfcCard;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for NFC card persistence operations.
 *
 * Follows Hexagonal Architecture: application defines the contract,
 * infrastructure provides the JPA implementation.
 */
public interface NfcCardRepositoryPort {

    Optional<NfcCard> findByCardSerialAndIsActiveTrue(String cardSerial);

    <S extends NfcCard> S save(S card);

    <S extends NfcCard> List<S> saveAll(Iterable<S> cards);

    boolean existsByCardSerialAndTenantId(String cardSerial, UUID tenantId);

    List<NfcCard> findByCardSerial(String cardSerial);

    List<NfcCard> findByUserIdAndIsActiveTrue(UUID userId);

    List<NfcCard> findByUserId(UUID userId);
}
