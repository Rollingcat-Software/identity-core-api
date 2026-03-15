package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.repository.GuestInvitationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class GuestInvitationRepositoryAdapter implements GuestInvitationRepositoryPort {

    private final GuestInvitationRepository jpaRepository;

    @Override
    public boolean existsActiveInvitation(UUID tenantId, String email) {
        return jpaRepository.existsActiveInvitation(tenantId, email);
    }

    @Override
    public GuestInvitation save(GuestInvitation invitation) {
        return jpaRepository.save(invitation);
    }

    @Override
    public Optional<GuestInvitation> findByInvitationToken(String token) {
        return jpaRepository.findByInvitationToken(token);
    }

    @Override
    public Optional<GuestInvitation> findActiveInvitationByTenantAndEmail(UUID tenantId, String email) {
        return jpaRepository.findActiveInvitationByTenantAndEmail(tenantId, email);
    }

    @Override
    public int expirePendingInvitations(Instant now) {
        return jpaRepository.expirePendingInvitations(now);
    }

    @Override
    public int expireAccessEndedInvitations(Instant now) {
        return jpaRepository.expireAccessEndedInvitations(now);
    }
}
