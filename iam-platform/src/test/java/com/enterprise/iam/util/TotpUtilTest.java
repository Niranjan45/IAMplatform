package com.enterprise.iam.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TotpUtilTest {

    private TotpUtil totpUtil;

    @BeforeEach
    void setUp() {
        totpUtil = new TotpUtil();
    }

    @Test
    void generateSecret_shouldReturnNonEmptyBase32String() {
        String secret = totpUtil.generateSecret();
        assertNotNull(secret);
        assertFalse(secret.isBlank());
        assertTrue(secret.matches("^[A-Z2-7]+$"), "Secret should be valid Base32");
    }

    @Test
    void generateSecret_shouldReturnDifferentSecretsEachTime() {
        String secret1 = totpUtil.generateSecret();
        String secret2 = totpUtil.generateSecret();
        assertNotEquals(secret1, secret2);
    }

    @Test
    void verifyCode_shouldAcceptCurrentlyValidCode() {
        String secret = totpUtil.generateSecret();
        // Generate a code the same way the util would internally by checking against itself:
        // we can't easily introspect the private method, so we validate round trip via buildOtpAuthUrl + manual window.
        long window = System.currentTimeMillis() / 1000 / 30;
        String code = generateCodeForTest(secret, window);
        assertTrue(totpUtil.verifyCode(secret, code));
    }

    @Test
    void verifyCode_shouldRejectInvalidCode() {
        String secret = totpUtil.generateSecret();
        assertFalse(totpUtil.verifyCode(secret, "000000"));
    }

    @Test
    void verifyCode_shouldRejectMalformedCode() {
        String secret = totpUtil.generateSecret();
        assertFalse(totpUtil.verifyCode(secret, "abc"));
        assertFalse(totpUtil.verifyCode(secret, null));
    }

    @Test
    void buildOtpAuthUrl_shouldContainExpectedParams() {
        String secret = totpUtil.generateSecret();
        String url = totpUtil.buildOtpAuthUrl(secret, "user@example.com", "Enterprise IAM");
        assertTrue(url.startsWith("otpauth://totp/"));
        assertTrue(url.contains("secret=" + secret));
        assertTrue(url.contains("digits=6"));
        assertTrue(url.contains("period=30"));
    }

    /** Mirrors TotpUtil's private algorithm just for test setup purposes. */
    private String generateCodeForTest(String base32Secret, long window) {
        try {
            var base32 = new org.apache.commons.codec.binary.Base32();
            byte[] key = base32.decode(base32Secret);
            byte[] data = new byte[8];
            long value = window;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>= 8;
            }
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);
            int otp = binary % 1_000_000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
