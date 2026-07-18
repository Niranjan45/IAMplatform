package com.enterprise.iam.controller;

import com.enterprise.iam.dto.request.ChangePasswordRequest;
import com.enterprise.iam.dto.request.MfaVerifyRequest;
import com.enterprise.iam.dto.request.UpdateProfileRequest;
import com.enterprise.iam.dto.response.ApiResponse;
import com.enterprise.iam.dto.response.MfaSetupResponse;
import com.enterprise.iam.dto.response.UserResponse;
import com.enterprise.iam.entity.User;
import com.enterprise.iam.security.CurrentUserResolver;
import com.enterprise.iam.service.MfaService;
import com.enterprise.iam.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
@Tag(name = "User Profile", description = "Self-service profile, password and MFA management for the logged-in user")
public class UserController {

    private final UserService userService;
    private final MfaService mfaService;
    private final CurrentUserResolver currentUserResolver;

    @GetMapping
    @Operation(summary = "Get the current user's profile")
    public ResponseEntity<ApiResponse<UserResponse>> getProfile() {
        User user = currentUserResolver.getCurrentUser();
        return ResponseEntity.ok(ApiResponse.success("Profile retrieved", userService.getProfile(user.getId())));
    }

    @PutMapping
    @Operation(summary = "Update the current user's profile")
    public ResponseEntity<ApiResponse<UserResponse>> updateProfile(@Valid @RequestBody UpdateProfileRequest request) {
        User user = currentUserResolver.getCurrentUser();
        return ResponseEntity.ok(ApiResponse.success("Profile updated", userService.updateProfile(user.getId(), request)));
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change the current user's password")
    public ResponseEntity<ApiResponse<Void>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        User user = currentUserResolver.getCurrentUser();
        userService.changePassword(user.getId(), request);
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully. Other sessions have been logged out."));
    }

    @PostMapping("/mfa/setup")
    @Operation(summary = "Begin MFA setup: generates a secret and QR code to scan with an authenticator app")
    public ResponseEntity<ApiResponse<MfaSetupResponse>> setupMfa() {
        User user = currentUserResolver.getCurrentUser();
        return ResponseEntity.ok(ApiResponse.success("Scan the QR code with your authenticator app, then confirm with a code", mfaService.setupMfa(user)));
    }

    @PostMapping("/mfa/confirm")
    @Operation(summary = "Confirm MFA setup with a code from the authenticator app to activate MFA")
    public ResponseEntity<ApiResponse<Void>> confirmMfa(@Valid @RequestBody MfaVerifyRequest request) {
        User user = currentUserResolver.getCurrentUser();
        mfaService.confirmMfa(user, request.code());
        return ResponseEntity.ok(ApiResponse.success("MFA has been enabled for your account"));
    }

    @PostMapping("/mfa/disable")
    @Operation(summary = "Disable MFA for the current user")
    public ResponseEntity<ApiResponse<Void>> disableMfa() {
        User user = currentUserResolver.getCurrentUser();
        mfaService.disableMfa(user);
        return ResponseEntity.ok(ApiResponse.success("MFA has been disabled for your account"));
    }
}
