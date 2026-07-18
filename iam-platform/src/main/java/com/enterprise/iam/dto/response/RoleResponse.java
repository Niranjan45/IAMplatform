package com.enterprise.iam.dto.response;

import com.enterprise.iam.entity.Role;

import java.util.Set;
import java.util.stream.Collectors;

public record RoleResponse(
        Long id,
        String name,
        String description,
        Set<String> permissions
) {
    public static RoleResponse fromEntity(Role role) {
        return new RoleResponse(
                role.getId(),
                role.getName(),
                role.getDescription(),
                role.getPermissions().stream().map(p -> p.getName()).collect(Collectors.toSet())
        );
    }
}
