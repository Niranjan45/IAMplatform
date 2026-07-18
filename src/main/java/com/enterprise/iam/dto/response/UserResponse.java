package com.enterprise.iam.dto.response;

import com.enterprise.iam.entity.User;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

public record UserResponse(
        Long id,
        String email,
        String username,
        String firstName,
        String lastName,
        String phoneNumber,
        boolean enabled,
        boolean emailVerified,
        boolean mfaEnabled,
        Set<String> roles,
        LocalDateTime lastLoginAt,
        LocalDateTime createdAt
) {
    public static UserResponse fromEntity(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getFirstName(),
                user.getLastName(),
                user.getPhoneNumber(),
                user.isEnabled(),
                user.isEmailVerified(),
                user.isMfaEnabled(),
                user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet()),
                user.getLastLoginAt(),
                user.getCreatedAt()
        );
    }
}
