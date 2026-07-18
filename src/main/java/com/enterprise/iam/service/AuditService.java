package com.enterprise.iam.service;

import com.enterprise.iam.entity.AuditLog;
import com.enterprise.iam.entity.User;
import com.enterprise.iam.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;

/**
 * Records security-relevant events (logins, password changes, admin actions, etc.)
 * Runs in its own REQUIRES_NEW transaction and asynchronously so that audit writes
 * never roll back or block the primary business transaction.
 */
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public enum Status { SUCCESS, FAILURE }

    @Async("taskExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(User user, String action, String entityType, String entityId, String details, Status status) {
        AuditLog log = AuditLog.builder()
                .userId(user != null ? user.getId() : null)
                .username(user != null ? user.getUsername() : "anonymous")
                .action(action)
                .entityType(entityType)
                .entityId(entityId)
                .details(details)
                .ipAddress(resolveClientIp())
                .status(status.name())
                .createdAt(LocalDateTime.now())
                .build();
        auditLogRepository.save(log);
    }

    public void log(String username, String action, String entityType, String entityId, String details, Status status) {
        AuditLog log = AuditLog.builder()
                .username(username)
                .action(action)
                .entityType(entityType)
                .entityId(entityId)
                .details(details)
                .ipAddress(resolveClientIp())
                .status(status.name())
                .createdAt(LocalDateTime.now())
                .build();
        auditLogRepository.save(log);
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
