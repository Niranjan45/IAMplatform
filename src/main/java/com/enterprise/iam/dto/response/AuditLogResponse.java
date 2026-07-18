package com.enterprise.iam.dto.response;

import com.enterprise.iam.entity.AuditLog;

import java.time.LocalDateTime;

public record AuditLogResponse(
        Long id,
        Long userId,
        String username,
        String action,
        String entityType,
        String entityId,
        String details,
        String ipAddress,
        String status,
        LocalDateTime createdAt
) {
    public static AuditLogResponse fromEntity(AuditLog log) {
        return new AuditLogResponse(
                log.getId(), log.getUserId(), log.getUsername(), log.getAction(),
                log.getEntityType(), log.getEntityId(), log.getDetails(),
                log.getIpAddress(), log.getStatus(), log.getCreatedAt()
        );
    }
}
