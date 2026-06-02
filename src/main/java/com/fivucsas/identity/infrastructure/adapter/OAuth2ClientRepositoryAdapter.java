package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.OAuth2ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class OAuth2ClientRepositoryAdapter implements OAuth2ClientRepositoryPort {

    private final OAuth2ClientRepository jpaRepository;
    private final TenantFilterBypass tenantFilterBypass;

    // An OAuth `client_id` is a GLOBAL unique key. Resolving a client by it is a
    // cross-tenant operation: the hosted-login / authorize / token endpoints must
    // find a first-party platform client (web dashboard, mobile app — bound to the
    // `system` tenant) regardless of the authenticated caller's ACTIVE tenant.
    // The OAuth2Client @Filter(tenantFilter) exists for tenant-scoped ADMIN LISTS,
    // not for these global-key lookups — so they run with the tenant filter
    // disabled (mirrors CustomUserDetailsService / MembershipSwitchAdapter). The
    // user↔client tenant policy is still enforced separately in
    // OAuth2Controller.validateAuthorizeRequest. OSIV provides the request session.

    @Override
    public Optional<OAuth2Client> findByClientIdAndActiveTrue(String clientId) {
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> jpaRepository.findByClientIdAndActiveTrue(clientId));
    }

    @Override
    public Optional<OAuth2Client> findByClientId(String clientId) {
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> jpaRepository.findByClientId(clientId));
    }

    @Override
    public boolean existsByClientId(String clientId) {
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> jpaRepository.existsByClientId(clientId));
    }

    @Override
    public List<OAuth2Client> findAllByTenantIdOrderByCreatedAtDesc(UUID tenantId) {
        // Tenant-scoped admin list — keep the tenant filter in effect.
        return jpaRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId);
    }

    @Override
    public Optional<OAuth2Client> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public <S extends OAuth2Client> S save(S client) {
        return jpaRepository.save(client);
    }

    @Override
    public void delete(OAuth2Client client) {
        jpaRepository.delete(client);
    }

    @Override
    public void deleteById(UUID id) {
        jpaRepository.deleteById(id);
    }
}
