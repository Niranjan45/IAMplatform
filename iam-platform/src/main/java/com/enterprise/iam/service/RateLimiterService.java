package com.enterprise.iam.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Simple Redis-backed fixed-window rate limiter, used to slow down brute-force
 * login attempts per source IP address independently of the per-account lockout
 * (which only kicks in once a specific username/email is targeted).
 */
@Service
@RequiredArgsConstructor
public class RateLimiterService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final int MAX_ATTEMPTS_PER_WINDOW = 20;
    private static final Duration WINDOW = Duration.ofMinutes(5);

    /** Returns true if the caller is within the allowed rate, false if they should be blocked. */
    public boolean tryAcquire(String key) {
        String redisKey = "ratelimit:login:" + key;
        Long count = redisTemplate.opsForValue().increment(redisKey);
        if (count != null && count == 1L) {
            redisTemplate.expire(redisKey, WINDOW);
        }
        return count == null || count <= MAX_ATTEMPTS_PER_WINDOW;
    }
}
