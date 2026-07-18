package com.enterprise.iam.service;

import com.enterprise.iam.entity.RefreshToken;
import com.enterprise.iam.entity.User;
import com.enterprise.iam.entity.UserSession;
import com.enterprise.iam.exception.InvalidTokenException;
import com.enterprise.iam.repository.RefreshTokenRepository;
import com.enterprise.iam.repository.UserSessionRepository;
import com.enterprise.iam.util.RandomTokenGenerator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;

/**
 * Manages opaque refresh tokens (persisted, revocable) and the parallel UserSession
 * records used for the "active sessions" / "log out other devices" admin features.
 */
@Service
@RequiredArgsConstructor
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserSessionRepository userSessionRepository;
    private final RandomTokenGenerator tokenGenerator;

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Transactional
    public RefreshToken issueRefreshToken(User user, String deviceInfo) {
        String token = tokenGenerator.generate();
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(token)
                .expiryDate(LocalDateTime.now().plusSeconds(refreshTokenExpirationMs / 1000))
                .revoked(false)
                .deviceInfo(deviceInfo)
                .ipAddress(resolveClientIp())
                .createdAt(LocalDateTime.now())
                .build();
        refreshTokenRepository.save(refreshToken);

        UserSession session = UserSession.builder()
                .user(user)
                .sessionToken(token)
                .deviceInfo(deviceInfo)
                .ipAddress(resolveClientIp())
                .active(true)
                .lastAccessedAt(LocalDateTime.now())
                .createdAt(LocalDateTime.now())
                .expiresAt(refreshToken.getExpiryDate())
                .build();
        userSessionRepository.save(session);

        return refreshToken;
    }

    @Transactional
    public RefreshToken rotateRefreshToken(String oldToken, String deviceInfo) {
        RefreshToken existing = refreshTokenRepository.findByTokenAndRevokedFalse(oldToken)
                .orElseThrow(() -> new InvalidTokenException("Refresh token is invalid or has already been used"));

        if (existing.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Refresh token has expired, please log in again");
        }

        existing.setRevoked(true);
        refreshTokenRepository.save(existing);
        userSessionRepository.deactivateByToken(oldToken);

        return issueRefreshToken(existing.getUser(), deviceInfo);
    }

    public User validateAndGetUser(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenAndRevokedFalse(token)
                .orElseThrow(() -> new InvalidTokenException("Refresh token is invalid or has already been used"));

        if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Refresh token has expired, please log in again");
        }
        return refreshToken.getUser();
    }

    @Transactional
    public void revokeToken(String token) {
        refreshTokenRepository.revokeByToken(token);
        userSessionRepository.deactivateByToken(token);
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllByUser(user);
        userSessionRepository.deactivateAllByUser(user);
    }

    private String resolveClientIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return "unknown";
            HttpServletRequest request = attrs.getRequest();
            String forwardedFor = request.getHeader("X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                return forwardedFor.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        } catch (Exception e) {
            return "unknown";
        }
    }
}
