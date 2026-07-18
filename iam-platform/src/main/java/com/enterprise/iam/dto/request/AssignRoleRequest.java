package com.enterprise.iam.dto.request;

import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record AssignRoleRequest(
        @NotEmpty Set<String> roleNames
) {
}
