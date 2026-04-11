package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.repository.NfcCardRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class NfcCardRepositoryAdapter implements NfcCardRepositoryPort {

    private final NfcCardRepository jpaRepository;

    @Override
    public Optional<NfcCard> findByCardSerialAndIsActiveTrue(String cardSerial) {
        return jpaRepository.findByCardSerialAndIsActiveTrue(cardSerial);
    }

    @Override
    public <S extends NfcCard> S save(S card) {
        return jpaRepository.save(card);
    }

    @Override
    public <S extends NfcCard> List<S> saveAll(Iterable<S> cards) {
        return jpaRepository.saveAll(cards);
    }

    @Override
    public boolean existsByCardSerialAndTenantId(String cardSerial, UUID tenantId) {
        return jpaRepository.existsByCardSerialAndTenantId(cardSerial, tenantId);
    }

    @Override
    public List<NfcCard> findByCardSerial(String cardSerial) {
        return jpaRepository.findByCardSerial(cardSerial);
    }

    @Override
    public List<NfcCard> findByUserIdAndIsActiveTrue(UUID userId) {
        return jpaRepository.findByUserIdAndIsActiveTrue(userId);
    }

    @Override
    public List<NfcCard> findByUserId(UUID userId) {
        return jpaRepository.findByUserId(userId);
    }

    @Override
    public boolean existsByCardSerialAndTenantIdAndIsActiveTrue(String cardSerial, UUID tenantId) {
        return jpaRepository.existsByCardSerialAndTenantIdAndIsActiveTrue(cardSerial, tenantId);
    }

    @Override
    public Optional<NfcCard> findByCardSerialAndUserIdAndIsActiveTrue(String cardSerial, UUID userId) {
        return jpaRepository.findByCardSerialAndUserIdAndIsActiveTrue(cardSerial, userId);
    }
}
