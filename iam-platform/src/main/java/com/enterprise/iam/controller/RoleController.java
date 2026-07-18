package com.enterprise.iam.controller;

import com.enterprise.iam.dto.request.CreateRoleRequest;
import com.enterprise.iam.dto.response.ApiResponse;
import com.enterprise.iam.dto.response.RoleResponse;
import com.enterprise.iam.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/admin/roles")
@RequiredArgsConstructor
@Tag(name = "Admin - Role Management", description = "Create, update and delete roles and their permission sets")
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_READ') or hasRole('ADMIN')")
    @Operation(summary = "List all roles")
    public ResponseEntity<ApiResponse<List<RoleResponse>>> getAllRoles() {
        return ResponseEntity.ok(ApiResponse.success("Roles retrieved", roleService.getAllRoles()));
    }

    @GetMapping("/{name}")
    @PreAuthorize("hasAuthority('ROLE_READ') or hasRole('ADMIN')")
    @Operation(summary = "Get a role by name")
    public ResponseEntity<ApiResponse<RoleResponse>> getRole(@PathVariable String name) {
        return ResponseEntity.ok(ApiResponse.success("Role retrieved", roleService.getRoleByName(name)));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Create a new role with an optional set of permissions")
    public ResponseEntity<ApiResponse<RoleResponse>> createRole(@Valid @RequestBody CreateRoleRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Role created", roleService.createRole(request)));
    }

    @PutMapping("/{name}/permissions")
    @PreAuthorize("hasAuthority('ROLE_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Replace the permission set assigned to a role")
    public ResponseEntity<ApiResponse<RoleResponse>> updatePermissions(@PathVariable String name,
                                                                        @RequestBody Set<String> permissionNames) {
        return ResponseEntity.ok(ApiResponse.success("Role permissions updated", roleService.updatePermissions(name, permissionNames)));
    }

    @DeleteMapping("/{name}")
    @PreAuthorize("hasAuthority('ROLE_DELETE') or hasRole('ADMIN')")
    @Operation(summary = "Delete a role")
    public ResponseEntity<ApiResponse<Void>> deleteRole(@PathVariable String name) {
        roleService.deleteRole(name);
        return ResponseEntity.ok(ApiResponse.success("Role deleted"));
    }
}
