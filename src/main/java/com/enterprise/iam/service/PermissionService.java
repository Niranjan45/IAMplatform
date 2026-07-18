package com.enterprise.iam.service;

import com.enterprise.iam.dto.request.CreatePermissionRequest;
import com.enterprise.iam.dto.response.PermissionResponse;
import com.enterprise.iam.entity.Permission;
import com.enterprise.iam.exception.DuplicateResourceException;
import com.enterprise.iam.exception.ResourceNotFoundException;
import com.enterprise.iam.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    @Transactional
    public PermissionResponse createPermission(CreatePermissionRequest request) {
        if (permissionRepository.existsByName(request.name())) {
            throw new DuplicateResourceException("A permission named '" + request.name() + "' already exists");
        }
        Permission permission = Permission.builder()
                .name(request.name())
                .description(request.description())
                .createdAt(LocalDateTime.now())
                .build();
        return PermissionResponse.fromEntity(permissionRepository.save(permission));
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> getAllPermissions() {
        return permissionRepository.findAll().stream().map(PermissionResponse::fromEntity).collect(Collectors.toList());
    }

    @Transactional
    public void deletePermission(String name) {
        Permission permission = permissionRepository.findByName(name)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found: " + name));
        permissionRepository.delete(permission);
    }
}
