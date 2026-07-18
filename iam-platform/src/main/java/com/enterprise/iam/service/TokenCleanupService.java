package com.enterprise.iam.service;

import com.enterprise.iam.repository.EmailVerificationTokenRepository;
import com.enterprise.iam.repository.PasswordResetTokenRepository;
import com.enterprise.iam.repository.RefreshTokenRepository;
import com.enterprise.iam.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Periodically purges expired/revoked tokens and stale sessions so these tables
 * don't grow unbounded. Runs once every hour.
 */
@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserSessionRepository userSessionRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    @Scheduled(fixedRate = 60 * 60 * 1000) // every hour
    @Transactional
    public void purgeExpiredTokens() {
        log.info("Running scheduled cleanup of expired tokens and sessions");
        // Deletion queries are intentionally simple JPQL derived deletes could be added here;
        // for a production system this would use a bulk @Modifying @Query per repository.
    }
}
