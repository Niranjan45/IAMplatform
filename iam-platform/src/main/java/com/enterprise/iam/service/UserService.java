package com.enterprise.iam.service;

import com.enterprise.iam.dto.request.AssignRoleRequest;
import com.enterprise.iam.dto.request.ChangePasswordRequest;
import com.enterprise.iam.dto.request.UpdateProfileRequest;
import com.enterprise.iam.dto.response.UserResponse;
import com.enterprise.iam.entity.Role;
import com.enterprise.iam.entity.User;
import com.enterprise.iam.exception.InvalidCredentialsException;
import com.enterprise.iam.exception.ResourceNotFoundException;
import com.enterprise.iam.repository.RoleRepository;
import com.enterprise.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @Transactional(readOnly = true)
    public UserResponse getProfile(Long userId) {
        return UserResponse.fromEntity(findUserOrThrow(userId));
    }

    @Transactional
    public UserResponse updateProfile(Long userId, UpdateProfileRequest request) {
        User user = findUserOrThrow(userId);
        if (request.firstName() != null) user.setFirstName(request.firstName());
        if (request.lastName() != null) user.setLastName(request.lastName());
        if (request.phoneNumber() != null) user.setPhoneNumber(request.phoneNumber());
        return UserResponse.fromEntity(userRepository.save(user));
    }

    @Transactional
    public void changePassword(Long userId, ChangePasswordRequest request) {
        User user = findUserOrThrow(userId);
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        // Changing password revokes all other sessions as a security best practice
        tokenService.revokeAllUserTokens(user);
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(UserResponse::fromEntity);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(Long userId) {
        return UserResponse.fromEntity(findUserOrThrow(userId));
    }

    @Transactional
    public UserResponse setUserEnabled(Long userId, boolean enabled) {
        User user = findUserOrThrow(userId);
        user.setEnabled(enabled);
        if (!enabled) {
            tokenService.revokeAllUserTokens(user);
        }
        return UserResponse.fromEntity(userRepository.save(user));
    }

    @Transactional
    public UserResponse unlockUser(Long userId) {
        User user = findUserOrThrow(userId);
        user.setAccountNonLocked(true);
        user.setFailedLoginAttempts(0);
        user.setLockTime(null);
        return UserResponse.fromEntity(userRepository.save(user));
    }

    @Transactional
    public UserResponse assignRoles(Long userId, AssignRoleRequest request) {
        User user = findUserOrThrow(userId);
        Set<Role> roles = request.roleNames().stream()
                .map(name -> roleRepository.findByName(name)
                        .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + name)))
                .collect(Collectors.toSet());
        user.setRoles(new HashSet<>(roles));
        return UserResponse.fromEntity(userRepository.save(user));
    }

    @Transactional
    public void deleteUser(Long userId) {
        User user = findUserOrThrow(userId);
        userRepository.delete(user);
    }

    User findUserOrThrow(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
    }
}
