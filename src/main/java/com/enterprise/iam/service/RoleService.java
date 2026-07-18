package com.enterprise.iam.service;

import com.enterprise.iam.dto.request.CreateRoleRequest;
import com.enterprise.iam.dto.response.RoleResponse;
import com.enterprise.iam.entity.Permission;
import com.enterprise.iam.entity.Role;
import com.enterprise.iam.exception.DuplicateResourceException;
import com.enterprise.iam.exception.ResourceNotFoundException;
import com.enterprise.iam.repository.PermissionRepository;
import com.enterprise.iam.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Transactional
    public RoleResponse createRole(CreateRoleRequest request) {
        if (roleRepository.existsByName(request.name())) {
            throw new DuplicateResourceException("A role named '" + request.name() + "' already exists");
        }

        Set<Permission> permissions = resolvePermissions(request.permissionNames());

        Role role = Role.builder()
                .name(request.name())
                .description(request.description())
                .permissions(permissions)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        return RoleResponse.fromEntity(roleRepository.save(role));
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> getAllRoles() {
        return roleRepository.findAll().stream().map(RoleResponse::fromEntity).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public RoleResponse getRoleByName(String name) {
        return RoleResponse.fromEntity(findRoleOrThrow(name));
    }

    @Transactional
    public RoleResponse updatePermissions(String roleName, Set<String> permissionNames) {
        Role role = findRoleOrThrow(roleName);
        role.setPermissions(resolvePermissions(permissionNames));
        role.setUpdatedAt(LocalDateTime.now());
        return RoleResponse.fromEntity(roleRepository.save(role));
    }

    @Transactional
    public void deleteRole(String roleName) {
        Role role = findRoleOrThrow(roleName);
        roleRepository.delete(role);
    }

    Role findRoleOrThrow(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + name));
    }

    private Set<Permission> resolvePermissions(Set<String> permissionNames) {
        if (permissionNames == null || permissionNames.isEmpty()) {
            return new HashSet<>();
        }
        return permissionNames.stream()
                .map(name -> permissionRepository.findByName(name)
                        .orElseThrow(() -> new ResourceNotFoundException("Permission not found: " + name)))
                .collect(Collectors.toSet());
    }
}
