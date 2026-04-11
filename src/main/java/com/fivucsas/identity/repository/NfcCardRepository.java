package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.NfcCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface NfcCardRepository extends JpaRepository<NfcCard, UUID> {

    Optional<NfcCard> findByCardSerialAndTenantId(String cardSerial, UUID tenantId);

    Optional<NfcCard> findByCardSerialAndIsActiveTrue(String cardSerial);

    List<NfcCard> findByCardSerial(String cardSerial);

    List<NfcCard> findByUserIdAndIsActiveTrue(UUID userId);

    List<NfcCard> findByUserId(UUID userId);

    List<NfcCard> findByTenantIdAndIsActiveTrue(UUID tenantId);

    boolean existsByCardSerialAndTenantId(String cardSerial, UUID tenantId);

    boolean existsByCardSerialAndTenantIdAndIsActiveTrue(String cardSerial, UUID tenantId);

    void deleteByUserIdAndTenantId(UUID userId, UUID tenantId);
}
