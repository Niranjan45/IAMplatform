package com.enterprise.iam.dto.response;

import com.enterprise.iam.entity.Permission;

public record PermissionResponse(
        Long id,
        String name,
        String description
) {
    public static PermissionResponse fromEntity(Permission permission) {
        return new PermissionResponse(permission.getId(), permission.getName(), permission.getDescription());
    }
}
