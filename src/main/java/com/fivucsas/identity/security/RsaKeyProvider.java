package com.fivucsas.identity.security;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Provides an RSA 2048-bit key pair used for RS256 JWT signing (BE-H1 remediation).
 *
 * Sources (in priority order):
 * 1. Environment variables JWT_RSA_PRIVATE_KEY_PEM / JWT_RSA_PUBLIC_KEY_PEM
 * 2. Spring properties fivucsas.jwt.rsa-private-key-pem / fivucsas.jwt.rsa-public-key-pem
 * 3. In the "dev" (or "test") profile only: auto-generate an ephemeral pair and log the PEMs
 *    so a developer can copy them into .env.
 *
 * In "prod" / any non-dev profile, missing keys trigger a fail-fast IllegalStateException.
 */
@Component
@Slf4j
public class RsaKeyProvider {

    public static final String DEFAULT_KID = "rs-2026-04";

    private static final String PRIV_ENV = "JWT_RSA_PRIVATE_KEY_PEM";
    private static final String PUB_ENV = "JWT_RSA_PUBLIC_KEY_PEM";

    @Value("${fivucsas.jwt.rsa-private-key-pem:}")
    private String configPrivatePem;

    @Value("${fivucsas.jwt.rsa-public-key-pem:}")
    private String configPublicPem;

    @Value("${fivucsas.jwt.rsa-kid:" + DEFAULT_KID + "}")
    private String kid;

    private final Environment environment;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public RsaKeyProvider(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    public void initialize() {
        String privPem = firstNonBlank(System.getenv(PRIV_ENV), configPrivatePem);
        String pubPem = firstNonBlank(System.getenv(PUB_ENV), configPublicPem);

        if (!isBlank(privPem) && !isBlank(pubPem)) {
            try {
                this.privateKey = parsePrivateKey(privPem);
                this.publicKey = parsePublicKey(pubPem);
                log.info("RSA JWT key pair loaded from environment/config. kid={}", kid);
                return;
            } catch (Exception e) {
                String msg = "CRITICAL SECURITY ERROR: Failed to parse RSA JWT key pair from env/config: "
                        + e.getMessage();
                log.error(msg);
                throw new IllegalStateException(msg, e);
            }
        }

        if (isDevOrTestProfile()) {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                KeyPair kp = gen.generateKeyPair();
                this.privateKey = (RSAPrivateKey) kp.getPrivate();
                this.publicKey = (RSAPublicKey) kp.getPublic();
                log.warn("RSA JWT key pair auto-generated for dev/test profile. kid={}. " +
                        "For stable dev usage, copy the following PEMs into .env as {} and {}:",
                        kid, PRIV_ENV, PUB_ENV);
                log.warn("{}=\n{}", PRIV_ENV, toPem("PRIVATE KEY", privateKey.getEncoded()));
                log.warn("{}=\n{}", PUB_ENV, toPem("PUBLIC KEY", publicKey.getEncoded()));
                return;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to auto-generate RSA key for dev profile", e);
            }
        }

        String errorMessage = String.format(
                "CRITICAL SECURITY ERROR: %s and %s environment variables are not set. " +
                "RSA JWT key pair is required for RS256 signing/verification in this profile. " +
                "Generate one with: openssl genrsa -out jwt_rs256.pem 2048",
                PRIV_ENV, PUB_ENV);
        log.error(errorMessage);
        throw new IllegalStateException(errorMessage);
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public String getKid() {
        return kid;
    }

    private boolean isDevOrTestProfile() {
        for (String p : environment.getActiveProfiles()) {
            if ("dev".equalsIgnoreCase(p) || "test".equalsIgnoreCase(p)) return true;
        }
        // No active profile in tests defaults to dev per application.yml
        if (environment.getActiveProfiles().length == 0) {
            for (String p : environment.getDefaultProfiles()) {
                if ("dev".equalsIgnoreCase(p) || "test".equalsIgnoreCase(p)) return true;
            }
            return true; // Safe default: tests / no profile -> dev behavior
        }
        return false;
    }

    private static RSAPrivateKey parsePrivateKey(String pem) throws Exception {
        String stripped = stripPem(pem, "PRIVATE KEY");
        byte[] decoded = Base64.getDecoder().decode(stripped);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    private static RSAPublicKey parsePublicKey(String pem) throws Exception {
        String stripped = stripPem(pem, "PUBLIC KEY");
        byte[] decoded = Base64.getDecoder().decode(stripped);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    private static String stripPem(String pem, String label) {
        return pem
                .replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "")
                .replaceAll("\\s+", "");
    }

    private static String toPem(String label, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----";
    }

    private static String firstNonBlank(String a, String b) {
        if (!isBlank(a)) return a;
        return b;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
