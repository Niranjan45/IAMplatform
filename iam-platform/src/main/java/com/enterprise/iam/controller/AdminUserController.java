package com.enterprise.iam.controller;

import com.enterprise.iam.dto.request.AssignRoleRequest;
import com.enterprise.iam.dto.response.ApiResponse;
import com.enterprise.iam.dto.response.UserResponse;
import com.enterprise.iam.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('USER_READ') or hasRole('ADMIN')")
@Tag(name = "Admin - User Management", description = "Administrative endpoints for managing user accounts")
public class AdminUserController {

    private final UserService userService;

    @GetMapping
    @Operation(summary = "List all users (paginated)")
    public ResponseEntity<ApiResponse<Page<UserResponse>>> getAllUsers(Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("Users retrieved", userService.getAllUsers(pageable)));
    }

    @GetMapping("/{userId}")
    @Operation(summary = "Get a user by ID")
    public ResponseEntity<ApiResponse<UserResponse>> getUser(@PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("User retrieved", userService.getUserById(userId)));
    }

    @PatchMapping("/{userId}/enable")
    @PreAuthorize("hasAuthority('USER_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Enable a user account")
    public ResponseEntity<ApiResponse<UserResponse>> enableUser(@PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("User enabled", userService.setUserEnabled(userId, true)));
    }

    @PatchMapping("/{userId}/disable")
    @PreAuthorize("hasAuthority('USER_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Disable a user account and revoke all of its active sessions")
    public ResponseEntity<ApiResponse<UserResponse>> disableUser(@PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("User disabled", userService.setUserEnabled(userId, false)));
    }

    @PatchMapping("/{userId}/unlock")
    @PreAuthorize("hasAuthority('USER_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Unlock a user account that was locked due to failed login attempts")
    public ResponseEntity<ApiResponse<UserResponse>> unlockUser(@PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("User unlocked", userService.unlockUser(userId)));
    }

    @PutMapping("/{userId}/roles")
    @PreAuthorize("hasAuthority('USER_WRITE') or hasRole('ADMIN')")
    @Operation(summary = "Replace a user's assigned roles")
    public ResponseEntity<ApiResponse<UserResponse>> assignRoles(@PathVariable Long userId,
                                                                  @Valid @RequestBody AssignRoleRequest request) {
        return ResponseEntity.ok(ApiResponse.success("Roles updated", userService.assignRoles(userId, request)));
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('USER_DELETE') or hasRole('ADMIN')")
    @Operation(summary = "Permanently delete a user account")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.ok(ApiResponse.success("User deleted"));
    }
}
