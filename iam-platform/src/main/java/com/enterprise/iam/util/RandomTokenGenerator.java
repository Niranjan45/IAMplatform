package com.enterprise.iam.util;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

/** Generates cryptographically strong, URL-safe opaque tokens (refresh tokens, reset tokens, etc.). */
@Component
public class RandomTokenGenerator {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public String generate() {
        return generate(48);
    }

    public String generate(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
