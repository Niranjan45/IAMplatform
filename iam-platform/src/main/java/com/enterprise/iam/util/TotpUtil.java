package com.enterprise.iam.util;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * RFC 6238 TOTP implementation (HMAC-SHA1, 30s step, 6 digits) used for the
 * Multi-Factor Authentication feature. Compatible with Google Authenticator,
 * Authy, and any other standard authenticator app.
 */
@Component
public class TotpUtil {

    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final String HMAC_ALGO = "HmacSHA1";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Generates a new random Base32-encoded secret suitable for an authenticator app. */
    public String generateSecret() {
        byte[] bytes = new byte[20];
        SECURE_RANDOM.nextBytes(bytes);
        return new Base32().encodeToString(bytes).replace("=", "");
    }

    /** Builds the otpauth:// URL used to render a QR code for authenticator apps. */
    public String buildOtpAuthUrl(String secret, String accountName, String issuer) {
        String encodedIssuer = urlEncode(issuer);
        String encodedAccount = urlEncode(accountName);
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
                encodedIssuer, encodedAccount, secret, encodedIssuer, CODE_DIGITS, TIME_STEP_SECONDS
        );
    }

    /** Validates a 6-digit code, allowing a +/-1 step window to tolerate clock drift. */
    public boolean verifyCode(String base32Secret, String code) {
        if (code == null || !code.matches("\\d{6}")) {
            return false;
        }
        long currentWindow = System.currentTimeMillis() / 1000 / TIME_STEP_SECONDS;
        for (long window = currentWindow - 1; window <= currentWindow + 1; window++) {
            if (generateCodeForWindow(base32Secret, window).equals(code)) {
                return true;
            }
        }
        return false;
    }

    private String generateCodeForWindow(String base32Secret, long window) {
        try {
            byte[] key = new Base32().decode(base32Secret);
            byte[] data = new byte[8];
            long value = window;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>= 8;
            }

            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate TOTP code", e);
        }
    }

    private String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
