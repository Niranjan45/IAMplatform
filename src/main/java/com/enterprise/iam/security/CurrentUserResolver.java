package com.enterprise.iam.security;

import com.enterprise.iam.entity.User;
import com.enterprise.iam.exception.ResourceNotFoundException;
import com.enterprise.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * The JWT filter authenticates using only the username as principal (to avoid an extra
 * DB hit per request just to build a UserDetails object). Controllers/services that need
 * the full User entity resolve it here, on demand, exactly once per request.
 */
@Component
@RequiredArgsConstructor
public class CurrentUserResolver {

    private final UserRepository userRepository;

    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user in the current security context");
        }
        String username = authentication.getName();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("Authenticated user not found: " + username));
    }
}
