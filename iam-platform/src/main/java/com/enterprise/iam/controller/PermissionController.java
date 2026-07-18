package com.enterprise.iam.controller;

import com.enterprise.iam.dto.request.CreatePermissionRequest;
import com.enterprise.iam.dto.response.ApiResponse;
import com.enterprise.iam.dto.response.PermissionResponse;
import com.enterprise.iam.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin/permissions")
@RequiredArgsConstructor
@Tag(name = "Admin - Permission Management", description = "Create, list and delete fine-grained permissions")
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping
    @PreAuthorize("hasAuthority('PERMISSION_READ') or hasRole('ADMIN')")
    @Operation(summary = "List all permissions")
    public ResponseEntity<ApiResponse<List<PermissionResponse>>> getAllPermissions() {
        return ResponseEntity.ok(ApiResponse.success("Permissions retrieved", permissionService.getAllPermissions()));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('PERMISSION_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Create a new permission")
    public ResponseEntity<ApiResponse<PermissionResponse>> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Permission created", permissionService.createPermission(request)));
    }

    @DeleteMapping("/{name}")
    @PreAuthorize("hasAuthority('PERMISSION_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Delete a permission")
    public ResponseEntity<ApiResponse<Void>> deletePermission(@PathVariable String name) {
        permissionService.deletePermission(name);
        return ResponseEntity.ok(ApiResponse.success("Permission deleted"));
    }
}
