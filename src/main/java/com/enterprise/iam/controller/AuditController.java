package com.enterprise.iam.controller;

import com.enterprise.iam.dto.response.ApiResponse;
import com.enterprise.iam.dto.response.AuditLogResponse;
import com.enterprise.iam.repository.AuditLogRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/audit-logs")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('AUDIT_READ') or hasRole('ADMIN')")
@Tag(name = "Admin - Audit Logs", description = "Query the security audit trail")
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping
    @Operation(summary = "List all audit log entries (paginated, most recent first)")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getAllLogs(Pageable pageable) {
        Page<AuditLogResponse> page = auditLogRepository.findAllByOrderByCreatedAtDesc(pageable)
                .map(AuditLogResponse::fromEntity);
        return ResponseEntity.ok(ApiResponse.success("Audit logs retrieved", page));
    }

    @GetMapping("/user/{userId}")
    @Operation(summary = "List audit log entries for a specific user")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getLogsForUser(@PathVariable Long userId, Pageable pageable) {
        Page<AuditLogResponse> page = auditLogRepository.findAllByUserIdOrderByCreatedAtDesc(userId, pageable)
                .map(AuditLogResponse::fromEntity);
        return ResponseEntity.ok(ApiResponse.success("Audit logs retrieved", page));
    }
}
