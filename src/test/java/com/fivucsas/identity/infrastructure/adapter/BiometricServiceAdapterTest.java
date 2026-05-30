package com.fivucsas.identity.infrastructure.adapter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link BiometricServiceAdapter} multipart forwarding.
 *
 * <p>Background: 2026-04-28 web-app reroute (Sec-P0b) eliminated the
 * {@code VITE_BIOMETRIC_API_KEY} from the SPA, routing all browser-originated
 * face calls through identity-core-api. The proxy adapter must forward both
 * {@code tenant_id} (for pgvector tenant scoping on bio side) and
 * {@code client_embedding(s)} (D2 log-only client telemetry) as multipart
 * parts so the bio side can scope queries and offline divergence analysis
 * keeps its signal.</p>
 *
 * <p>This test uses {@link MockRestServiceServer} to intercept the outbound
 * call and assert the multipart payload contains the expected parts.</p>
 */
@DisplayName("BiometricServiceAdapter — tenant_id + client_embedding(s) forwarding")
class BiometricServiceAdapterTest {

    private BiometricServiceAdapter adapter;
    private MockRestServiceServer mockServer;

    private static final String BIO_URL = "http://bio.localhost:8001";
    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final String TENANT_ID = "tenant-marmara";
    private static final String CLIENT_EMBEDDING = "[0.1,0.2,0.3]";
    private static final String CLIENT_EMBEDDINGS = "[[0.1,0.2],[0.3,0.4]]";

    private MultipartFile imageFile;

    @BeforeEach
    void setUp() throws Exception {
        // Construct the adapter normally, then mutate its internal RestClient
        // to install a MockRestServiceServer-bound request factory. We use
        // RestClient#mutate() (Spring 6.1+) so the mock replaces the real
        // SimpleClientHttpRequestFactory wired in the adapter constructor.
        adapter = new BiometricServiceAdapter(
                RestClient.builder(), BIO_URL, "", 5000, 30000);

        Field restClientField = BiometricServiceAdapter.class.getDeclaredField("restClient");
        restClientField.setAccessible(true);
        RestClient original = (RestClient) restClientField.get(adapter);

        RestClient.Builder mutated = original.mutate();
        mockServer = MockRestServiceServer.bindTo(mutated).build();
        restClientField.set(adapter, mutated.build());

        imageFile = new MockMultipartFile(
                "file", "face.jpg", "image/jpeg", "fake-image-bytes".getBytes());
    }

    private static String bodyAsString(org.springframework.http.client.ClientHttpRequest req) {
        try {
            return ((ByteArrayOutputStream) req.getBody()).toString();
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("enrollFace forwards tenant_id and client_embedding multipart parts")
    void enrollFace_forwardsTenantAndEmbedding() {
        mockServer.expect(requestTo(BIO_URL + "/enroll"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("name=\"tenant_id\"")
                            .contains(TENANT_ID)
                            .contains("name=\"client_embedding\"")
                            .contains(CLIENT_EMBEDDING)
                            .contains("name=\"user_id\"")
                            .contains("name=\"file\"");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.enrollFace(USER_ID, imageFile, TENANT_ID, CLIENT_EMBEDDING, null);

        assertThat(result).containsEntry("success", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyFace forwards tenant_id and client_embeddings (array form)")
    void verifyFace_forwardsTenantAndEmbeddingsArray() {
        mockServer.expect(requestTo(BIO_URL + "/verify"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("name=\"tenant_id\"")
                            .contains(TENANT_ID)
                            .contains("name=\"client_embeddings\"")
                            .contains(CLIENT_EMBEDDINGS);
                })
                .andRespond(withSuccess("{\"verified\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.verifyFace(USER_ID, imageFile, TENANT_ID, null, CLIENT_EMBEDDINGS);

        assertThat(result).containsEntry("verified", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("searchFace forwards tenant_id multipart part")
    void searchFace_forwardsTenant() {
        mockServer.expect(requestTo(BIO_URL + "/search"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("name=\"tenant_id\"")
                            .contains(TENANT_ID)
                            .contains("name=\"file\"");
                })
                .andRespond(withSuccess("{\"matches\":[]}", MediaType.APPLICATION_JSON));

        var result = adapter.searchFace(imageFile, TENANT_ID, null, null);

        assertThat(result).containsKey("matches");
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollFaceMulti forwards tenant_id and client_embedding for multi-image")
    void enrollFaceMulti_forwardsTenantAndEmbedding() {
        MultipartFile img2 = new MockMultipartFile(
                "file", "face2.jpg", "image/jpeg", "fake-image-2".getBytes());

        mockServer.expect(requestTo(BIO_URL + "/enroll/multi"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("name=\"tenant_id\"")
                            .contains(TENANT_ID)
                            .contains("name=\"client_embedding\"")
                            .contains(CLIENT_EMBEDDING)
                            .contains("name=\"user_id\"")
                            .contains("name=\"files\"");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.enrollFaceMulti(
                USER_ID, List.of(imageFile, img2), TENANT_ID, CLIENT_EMBEDDING, null);

        assertThat(result).containsEntry("success", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("Backward-compat: legacy 2-arg enrollFace omits optional parts")
    void enrollFace_backwardCompat_noTenantOrEmbedding() {
        mockServer.expect(requestTo(BIO_URL + "/enroll"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    // Required parts still there
                    assertThat(body).contains("name=\"user_id\"")
                            .contains("name=\"file\"");
                    // Optional parts must NOT be present when null was passed
                    assertThat(body).doesNotContain("name=\"tenant_id\"")
                            .doesNotContain("name=\"client_embedding\"");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        // Use the legacy 2-arg signature (default method on the port)
        var result = adapter.enrollFace(USER_ID, imageFile);

        assertThat(result).containsEntry("success", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("Blank tenant_id is omitted from multipart body")
    void enrollFace_blankTenant_isOmitted() {
        mockServer.expect(requestTo(BIO_URL + "/enroll"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).doesNotContain("name=\"tenant_id\"");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        adapter.enrollFace(USER_ID, imageFile, "   ", null, null);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyNfcChipAuthenticity posts the frozen contract: sod_b64 + numeric data_groups to /api/v1/nfc/verify-authenticity")
    void verifyNfcChipAuthenticity_postsFrozenContract() {
        mockServer.expect(requestTo(BIO_URL + "/api/v1/nfc/verify-authenticity"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    // sod_b64 field present with the SOD value
                    assertThat(body).contains("\"sod_b64\"").contains("SODBYTES");
                    // data_groups object with bio-native numeric keys ("1","2"),
                    // NOT the client's "dg1"/"dg2" form
                    assertThat(body).contains("\"data_groups\"")
                            .contains("\"1\"").contains("DG1BYTES")
                            .contains("\"2\"").contains("DG2BYTES");
                    assertThat(body).doesNotContain("\"dg1\"");
                })
                .andRespond(withSuccess(
                        "{\"is_authentic\":true,\"reason_code\":\"OK\"}", MediaType.APPLICATION_JSON));

        // Caller passes dg-prefixed keys; the adapter normalizes to numeric.
        var result = adapter.verifyNfcChipAuthenticity("SODBYTES",
                java.util.Map.of("dg1", "DG1BYTES", "dg2", "DG2BYTES"));

        assertThat(result).containsEntry("is_authentic", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyNfcChipAuthenticity surfaces a 4xx from bio as a fail-closed error map")
    void verifyNfcChipAuthenticity_4xx_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/api/v1/nfc/verify-authenticity"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
                        .body("{\"detail\":\"bad sod\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        // Non-empty DG so the call actually reaches bio (empty DG short-circuits).
        var result = adapter.verifyNfcChipAuthenticity("BADSOD", java.util.Map.of("dg1", "DG1"));

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyNfcChipAuthenticity with NO data groups short-circuits fail-closed (MISSING_DG), no bio call")
    void verifyNfcChipAuthenticity_noDataGroups_shortCircuits() {
        // No mockServer.expect(...) — the adapter must NOT make an outbound call.
        var result = adapter.verifyNfcChipAuthenticity("SODBYTES", java.util.Map.of());

        assertThat(result).containsEntry("is_authentic", false);
        assertThat(result).containsEntry("reason_code", "MISSING_DG");
        mockServer.verify(); // verifies zero expected requests were made
    }
}
