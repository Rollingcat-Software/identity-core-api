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
    @DisplayName("enrollFace forwards optimize=true multipart part on re-enroll & optimize")
    void enrollFace_forwardsOptimizeWhenTrue() {
        mockServer.expect(requestTo(BIO_URL + "/enroll"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("name=\"optimize\"")
                            .contains("true")
                            .contains("name=\"user_id\"")
                            .contains("name=\"file\"");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.enrollFace(USER_ID, imageFile, TENANT_ID, null, null, true);

        assertThat(result).containsEntry("success", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollFace omits the optimize part on a normal enroll (optimize=false)")
    void enrollFace_omitsOptimizeWhenFalse() {
        mockServer.expect(requestTo(BIO_URL + "/enroll"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).doesNotContain("name=\"optimize\"");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        adapter.enrollFace(USER_ID, imageFile, TENANT_ID, null, null, false);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollVoice forwards optimize=true in the JSON body on re-enroll & optimize")
    void enrollVoice_forwardsOptimizeWhenTrue() {
        mockServer.expect(requestTo(BIO_URL + "/voice/enroll"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"optimize\":true");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.enrollVoice(USER_ID, "base64-voice-data", true);

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

    // --- hasEnrollment (flag-consistency reconciler backing) ---

    @Test
    @DisplayName("hasEnrollment returns true when the tenant export lists the user_id")
    void hasEnrollment_userPresentInExport_returnsTrue() {
        mockServer.expect(requestTo(BIO_URL + "/embeddings/export?tenant_id=" + TENANT_ID + "&include_metadata=false"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"count\":2,\"embeddings\":[{\"user_id\":\"" + USER_ID + "\"},"
                                + "{\"user_id\":\"99999999-0000-0000-0000-000000000000\"}]}",
                        MediaType.APPLICATION_JSON));

        assertThat(adapter.hasEnrollment(USER_ID, TENANT_ID)).isTrue();
        mockServer.verify();
    }

    @Test
    @DisplayName("hasEnrollment returns false when the user_id is absent from the tenant export")
    void hasEnrollment_userAbsentFromExport_returnsFalse() {
        mockServer.expect(requestTo(BIO_URL + "/embeddings/export?tenant_id=" + TENANT_ID + "&include_metadata=false"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"count\":1,\"embeddings\":[{\"user_id\":\"99999999-0000-0000-0000-000000000000\"}]}",
                        MediaType.APPLICATION_JSON));

        assertThat(adapter.hasEnrollment(USER_ID, TENANT_ID)).isFalse();
        mockServer.verify();
    }

    @Test
    @DisplayName("hasEnrollment fails CLOSED (false) when the bio service errors")
    void hasEnrollment_bioError_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/embeddings/export?tenant_id=" + TENANT_ID + "&include_metadata=false"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("boom").contentType(MediaType.TEXT_PLAIN));

        assertThat(adapter.hasEnrollment(USER_ID, TENANT_ID)).isFalse();
        mockServer.verify();
    }

    @Test
    @DisplayName("hasEnrollment falls back to the 'default' tenant when tenantId is blank")
    void hasEnrollment_blankTenant_usesDefault() {
        mockServer.expect(requestTo(BIO_URL + "/embeddings/export?tenant_id=default&include_metadata=false"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"count\":1,\"embeddings\":[{\"user_id\":\"" + USER_ID + "\"}]}",
                        MediaType.APPLICATION_JSON));

        assertThat(adapter.hasEnrollment(USER_ID, "  ")).isTrue();
        mockServer.verify();
    }

    @Test
    @DisplayName("hasEnrollment returns false for a null userId without calling bio")
    void hasEnrollment_nullUser_returnsFalseNoCall() {
        assertThat(adapter.hasEnrollment(null, TENANT_ID)).isFalse();
        mockServer.verify(); // zero outbound calls
    }

    // --- client-side embedding (sub-project A, Phase 5) ---

    private static final List<Double> EMBEDDING = List.of(0.11, -0.22, 0.33);

    @Test
    @DisplayName("verifyEmbedding posts user_id + embedding + tenant_id as JSON to /verify-embedding")
    void verifyEmbedding_postsJson() {
        mockServer.expect(requestTo(BIO_URL + "/verify-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"user_id\"").contains(USER_ID.toString());
                    assertThat(body).contains("\"embedding\"")
                            .contains("0.11").contains("-0.22").contains("0.33");
                    assertThat(body).contains("\"tenant_id\"").contains(TENANT_ID);
                })
                .andRespond(withSuccess("{\"verified\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.verifyEmbedding(TENANT_ID, USER_ID, EMBEDDING);

        assertThat(result).containsEntry("verified", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyEmbedding omits a blank tenant_id from the JSON body")
    void verifyEmbedding_blankTenant_isOmitted() {
        mockServer.expect(requestTo(BIO_URL + "/verify-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"embedding\"");
                    assertThat(body).doesNotContain("\"tenant_id\"");
                })
                .andRespond(withSuccess("{\"verified\":false}", MediaType.APPLICATION_JSON));

        adapter.verifyEmbedding("  ", USER_ID, EMBEDDING);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyEmbedding maps a bio 4xx to a fail-closed error map")
    void verifyEmbedding_4xx_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/verify-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
                        .body("{\"detail\":\"bad embedding\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        var result = adapter.verifyEmbedding(TENANT_ID, USER_ID, EMBEDDING);

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollEmbedding posts user_id + embedding + tenant_id as JSON to /enroll-embedding")
    void enrollEmbedding_postsJson() {
        mockServer.expect(requestTo(BIO_URL + "/enroll-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"user_id\"").contains(USER_ID.toString());
                    assertThat(body).contains("\"embedding\"")
                            .contains("0.11").contains("-0.22").contains("0.33");
                    assertThat(body).contains("\"tenant_id\"").contains(TENANT_ID);
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.enrollEmbedding(TENANT_ID, USER_ID, EMBEDDING);

        assertThat(result).containsEntry("success", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollEmbedding maps bio unreachable to a fail-closed error map")
    void enrollEmbedding_unreachable_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/enroll-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(req -> {
                    throw new org.springframework.web.client.ResourceAccessException("connection refused");
                });

        var result = adapter.enrollEmbedding(TENANT_ID, USER_ID, EMBEDDING);

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }

    // --- client-side VOICE embedding (audit H3, GPU-less) ---

    @Test
    @DisplayName("verifyVoiceEmbedding posts user_id + embedding (+tenant_id) to /voice/verify-embedding")
    void verifyVoiceEmbedding_postsJson() {
        mockServer.expect(requestTo(BIO_URL + "/voice/verify-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"user_id\"").contains(USER_ID.toString());
                    assertThat(body).contains("\"embedding\"")
                            .contains("0.11").contains("-0.22").contains("0.33");
                    assertThat(body).contains("\"tenant_id\"").contains(TENANT_ID);
                })
                .andRespond(withSuccess("{\"verified\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.verifyVoiceEmbedding(TENANT_ID, USER_ID, EMBEDDING);

        assertThat(result).containsEntry("verified", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("verifyVoiceEmbedding maps a bio 4xx to a fail-closed error map")
    void verifyVoiceEmbedding_4xx_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/voice/verify-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY)
                        .body("{\"detail\":\"embedding must have exactly 256 elements\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        var result = adapter.verifyVoiceEmbedding(TENANT_ID, USER_ID, EMBEDDING);

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollVoiceEmbedding posts user_id + embedding + optimize to /voice/enroll-embedding")
    void enrollVoiceEmbedding_postsJsonWithOptimize() {
        mockServer.expect(requestTo(BIO_URL + "/voice/enroll-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"user_id\"").contains(USER_ID.toString());
                    assertThat(body).contains("\"embedding\"").contains("0.11");
                    assertThat(body).contains("\"tenant_id\"").contains(TENANT_ID);
                    assertThat(body).contains("\"optimize\":true");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.enrollVoiceEmbedding(TENANT_ID, USER_ID, EMBEDDING, true);

        assertThat(result).containsEntry("success", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollVoiceEmbedding omits a blank tenant_id and defaults optimize=false")
    void enrollVoiceEmbedding_blankTenant_omitted() {
        mockServer.expect(requestTo(BIO_URL + "/voice/enroll-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"embedding\"");
                    assertThat(body).doesNotContain("\"tenant_id\"");
                    assertThat(body).contains("\"optimize\":false");
                })
                .andRespond(withSuccess("{\"success\":true}", MediaType.APPLICATION_JSON));

        adapter.enrollVoiceEmbedding("  ", USER_ID, EMBEDDING, false);
        mockServer.verify();
    }

    @Test
    @DisplayName("enrollVoiceEmbedding maps bio unreachable to a fail-closed error map")
    void enrollVoiceEmbedding_unreachable_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/voice/enroll-embedding"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(req -> {
                    throw new org.springframework.web.client.ResourceAccessException("connection refused");
                });

        var result = adapter.enrollVoiceEmbedding(TENANT_ID, USER_ID, EMBEDDING, false);

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }

    // --- puzzle session proxy (CV-2 of the puzzle-as-login convergence) ---
    // Canonical bio routes (relative to the /api/v1 base URL):
    //   POST /liveness/puzzle-session
    //   POST /liveness/puzzle-session/{id}/challenge
    //   POST /liveness/puzzle-session/{id}/verdict
    private static final UUID PUZZLE_TENANT = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final String PUZZLE_SESSION_ID = "tok_opaque_abc123";

    @Test
    @DisplayName("createPuzzleSession posts tenant_id + user_id + allowed_challenge_types + count + difficulty as JSON")
    void createPuzzleSession_postsContractBody() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"tenant_id\"").contains(PUZZLE_TENANT.toString());
                    assertThat(body).contains("\"user_id\"").contains(USER_ID.toString());
                    assertThat(body).contains("\"allowed_challenge_types\"")
                            .contains("blink").contains("smile");
                    assertThat(body).contains("\"count\"").contains("2");
                    assertThat(body).contains("\"difficulty\"").contains("standard");
                })
                .andRespond(withSuccess(
                        "{\"session_id\":\"" + PUZZLE_SESSION_ID + "\",\"challenges\":["
                                + "{\"action\":\"blink\",\"params\":null},"
                                + "{\"action\":\"smile\",\"params\":null}]}",
                        MediaType.APPLICATION_JSON));

        var result = adapter.createPuzzleSession(
                PUZZLE_TENANT, USER_ID, List.of("blink", "smile"), 2, "standard");

        assertThat(result).containsEntry("session_id", PUZZLE_SESSION_ID);
        assertThat(result).containsKey("challenges");
        mockServer.verify();
    }

    @Test
    @DisplayName("createPuzzleSession omits a null difficulty from the JSON body")
    void createPuzzleSession_nullDifficulty_omitted() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"allowed_challenge_types\"");
                    assertThat(body).doesNotContain("\"difficulty\"");
                })
                .andRespond(withSuccess(
                        "{\"session_id\":\"" + PUZZLE_SESSION_ID + "\",\"challenges\":[]}",
                        MediaType.APPLICATION_JSON));

        adapter.createPuzzleSession(PUZZLE_TENANT, USER_ID, List.of("blink"), 1, null);
        mockServer.verify();
    }

    @Test
    @DisplayName("createPuzzleSession maps a bio 4xx to a fail-closed error map (no session_id)")
    void createPuzzleSession_4xx_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
                        .body("{\"detail\":\"empty allowed types\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        var result = adapter.createPuzzleSession(PUZZLE_TENANT, USER_ID, List.of("blink"), 1, null);

        assertThat(result).containsEntry("success", false);
        assertThat(result).doesNotContainKey("session_id");
        mockServer.verify();
    }

    @Test
    @DisplayName("createPuzzleSession maps bio unreachable to a fail-closed error map")
    void createPuzzleSession_unreachable_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(req -> {
                    throw new org.springframework.web.client.ResourceAccessException("connection refused");
                });

        var result = adapter.createPuzzleSession(PUZZLE_TENANT, USER_ID, List.of("blink"), 1, null);

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }

    @Test
    @DisplayName("submitPuzzleChallenge posts the body to /puzzle-session/{id}/challenge and returns the per-challenge verdict")
    void submitPuzzleChallenge_postsBody() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session/" + PUZZLE_SESSION_ID + "/challenge"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"action\"").contains("blink");
                    assertThat(body).contains("\"metrics\"").contains("ear");
                    assertThat(body).contains("\"confidence\"");
                })
                .andRespond(withSuccess(
                        "{\"verified\":true,\"action\":\"blink\",\"reason_code\":null}",
                        MediaType.APPLICATION_JSON));

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("action", "blink");
        body.put("metrics", java.util.Map.of("ear", 0.18));
        body.put("start_timestamp_ms", 1_000_000.0);
        body.put("end_timestamp_ms", 1_002_500.0);
        body.put("confidence", 0.92);

        var result = adapter.submitPuzzleChallenge(PUZZLE_SESSION_ID, body);

        assertThat(result).containsEntry("verified", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("submitPuzzleChallenge maps a bio 404 (unknown/expired/consumed) to a fail-closed error map")
    void submitPuzzleChallenge_404_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session/" + PUZZLE_SESSION_ID + "/challenge"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.NOT_FOUND)
                        .body("{\"detail\":\"SESSION_NOT_FOUND\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        var result = adapter.submitPuzzleChallenge(PUZZLE_SESSION_ID, java.util.Map.of("action", "blink"));

        assertThat(result).containsEntry("success", false);
        assertThat(result).doesNotContainKey("verified");
        mockServer.verify();
    }

    @Test
    @DisplayName("getPuzzleVerdict posts user_id + tenant_id to /puzzle-session/{id}/verdict and returns the verdict")
    void getPuzzleVerdict_postsOwnerIdentity() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session/" + PUZZLE_SESSION_ID + "/verdict"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(req -> {
                    String body = bodyAsString(req);
                    assertThat(body).contains("\"user_id\"").contains(USER_ID.toString());
                    assertThat(body).contains("\"tenant_id\"").contains(PUZZLE_TENANT.toString());
                })
                .andRespond(withSuccess("{\"verified\":true}", MediaType.APPLICATION_JSON));

        var result = adapter.getPuzzleVerdict(PUZZLE_SESSION_ID, USER_ID, PUZZLE_TENANT);

        assertThat(result).containsEntry("verified", true);
        mockServer.verify();
    }

    @Test
    @DisplayName("getPuzzleVerdict maps a bio 404 (unknown/expired) to a fail-closed error map (no `verified`)")
    void getPuzzleVerdict_404_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session/" + PUZZLE_SESSION_ID + "/verdict"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.NOT_FOUND)
                        .body("{\"detail\":\"SESSION_EXPIRED\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        var result = adapter.getPuzzleVerdict(PUZZLE_SESSION_ID, USER_ID, PUZZLE_TENANT);

        assertThat(result).containsEntry("success", false);
        assertThat(result).doesNotContainKey("verified");
        mockServer.verify();
    }

    @Test
    @DisplayName("getPuzzleVerdict maps bio unreachable to a fail-closed error map")
    void getPuzzleVerdict_unreachable_failsClosed() {
        mockServer.expect(requestTo(BIO_URL + "/liveness/puzzle-session/" + PUZZLE_SESSION_ID + "/verdict"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(req -> {
                    throw new org.springframework.web.client.ResourceAccessException("connection refused");
                });

        var result = adapter.getPuzzleVerdict(PUZZLE_SESSION_ID, USER_ID, PUZZLE_TENANT);

        assertThat(result).containsEntry("success", false);
        mockServer.verify();
    }
}
