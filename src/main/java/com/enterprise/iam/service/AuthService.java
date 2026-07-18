package com.enterprise.iam.service;

import com.enterprise.iam.dto.request.*;
import com.enterprise.iam.dto.response.AuthResponse;
import com.enterprise.iam.dto.response.UserResponse;
import com.enterprise.iam.entity.*;
import com.enterprise.iam.exception.*;
import com.enterprise.iam.repository.*;
import com.enterprise.iam.security.JwtService;
import com.enterprise.iam.security.SecurityUserDetails;
import com.enterprise.iam.util.RandomTokenGenerator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenService tokenService;
    private final MfaService mfaService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final RandomTokenGenerator tokenGenerator;

    @Value("${app.security.max-failed-login-attempts}")
    private int maxFailedAttempts;

    @Value("${app.security.account-lockout-duration-minutes}")
    private long lockoutDurationMinutes;

    @Value("${app.security.password-reset-token-expiration-minutes}")
    private long passwordResetExpirationMinutes;

    @Value("${app.security.email-verification-token-expiration-hours}")
    private long emailVerificationExpirationHours;

    private static final String DEFAULT_ROLE = "ROLE_USER";

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new DuplicateResourceException("An account with this email already exists");
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new DuplicateResourceException("This username is already taken");
        }

        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Default role '" + DEFAULT_ROLE + "' is not configured"));

        Set<Role> roles = new HashSet<>();
        roles.add(defaultRole);

        User user = User.builder()
                .email(request.email())
                .username(request.username())
                .passwordHash(passwordEncoder.encode(request.password()))
                .firstName(request.firstName())
                .lastName(request.lastName())
                .phoneNumber(request.phoneNumber())
                .enabled(true)
                .emailVerified(false)
                .accountNonLocked(true)
                .mfaEnabled(false)
                .roles(roles)
                .build();

        user = userRepository.save(user);

        String verificationToken = tokenGenerator.generate(32);
        EmailVerificationToken evt = EmailVerificationToken.builder()
                .user(user)
                .token(verificationToken)
                .expiryDate(LocalDateTime.now().plusHours(emailVerificationExpirationHours))
                .used(false)
                .createdAt(LocalDateTime.now())
                .build();
        emailVerificationTokenRepository.save(evt);

        emailService.sendVerificationEmail(user.getEmail(), verificationToken);
        auditService.log(user, "USER_REGISTERED", "User", user.getId().toString(), "New account registered", AuditService.Status.SUCCESS);

        return UserResponse.fromEntity(user);
    }

    @Transactional
    public void verifyEmail(String token) {
        EmailVerificationToken evt = emailVerificationTokenRepository.findByTokenAndUsedFalse(token)
                .orElseThrow(() -> new InvalidTokenException("Verification link is invalid or has already been used"));

        if (evt.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Verification link has expired. Please request a new one.");
        }

        User user = evt.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        evt.setUsed(true);
        emailVerificationTokenRepository.save(evt);

        auditService.log(user, "EMAIL_VERIFIED", "User", user.getId().toString(), null, AuditService.Status.SUCCESS);
    }

    @Transactional
    public AuthResponse login(LoginRequest request, String deviceInfo) {
        User user = userRepository.findByEmailOrUsername(request.usernameOrEmail(), request.usernameOrEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        enforceLockoutCheck(user);

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerFailedAttempt(user);
            throw new InvalidCredentialsException("Invalid username or password");
        }

        if (!user.isEnabled()) {
            throw new AccountLockedException("This account has been disabled. Please contact an administrator.");
        }

        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException("Please verify your email address before logging in");
        }

        if (user.isMfaEnabled()) {
            if (request.otp() == null || request.otp().isBlank()) {
                return AuthResponse.ofMfaRequired();
            }
            if (!mfaService.verifyCode(user, request.otp())) {
                registerFailedAttempt(user);
                throw new InvalidCredentialsException("Invalid MFA code");
            }
        }

        resetFailedAttempts(user);
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        SecurityUserDetails principal = new SecurityUserDetails(user);
        String accessToken = jwtService.generateAccessToken(principal);
        RefreshToken refreshToken = tokenService.issueRefreshToken(user, deviceInfo);

        auditService.log(user, "LOGIN_SUCCESS", "User", user.getId().toString(), null, AuditService.Status.SUCCESS);

        return AuthResponse.of(accessToken, refreshToken.getToken(), jwtService.getAccessTokenExpirationMs() / 1000, UserResponse.fromEntity(user));
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, String deviceInfo) {
        RefreshToken rotated = tokenService.rotateRefreshToken(request.refreshToken(), deviceInfo);
        User user = rotated.getUser();
        SecurityUserDetails principal = new SecurityUserDetails(user);
        String accessToken = jwtService.generateAccessToken(principal);

        return AuthResponse.of(accessToken, rotated.getToken(), jwtService.getAccessTokenExpirationMs() / 1000, UserResponse.fromEntity(user));
    }

    @Transactional
    public void logout(String refreshToken) {
        tokenService.revokeToken(refreshToken);
    }

    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        userRepository.findByEmail(request.email()).ifPresent(user -> {
            String token = tokenGenerator.generate(32);
            PasswordResetToken resetToken = PasswordResetToken.builder()
                    .user(user)
                    .token(token)
                    .expiryDate(LocalDateTime.now().plusMinutes(passwordResetExpirationMinutes))
                    .used(false)
                    .createdAt(LocalDateTime.now())
                    .build();
            passwordResetTokenRepository.save(resetToken);
            emailService.sendPasswordResetEmail(user.getEmail(), token);
            auditService.log(user, "PASSWORD_RESET_REQUESTED", "User", user.getId().toString(), null, AuditService.Status.SUCCESS);
        });
        // Intentionally always return success-like behavior regardless of whether the email
        // exists, so this endpoint cannot be used to enumerate registered accounts.
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByTokenAndUsedFalse(request.token())
                .orElseThrow(() -> new InvalidTokenException("Reset link is invalid or has already been used"));

        if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Reset link has expired. Please request a new one.");
        }

        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setAccountNonLocked(true);
        user.setFailedLoginAttempts(0);
        user.setLockTime(null);
        userRepository.save(user);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);

        // Force re-authentication everywhere after a password reset
        tokenService.revokeAllUserTokens(user);

        auditService.log(user, "PASSWORD_RESET_COMPLETED", "User", user.getId().toString(), null, AuditService.Status.SUCCESS);
    }

    private void enforceLockoutCheck(User user) {
        if (!user.isAccountNonLocked()) {
            if (user.getLockTime() != null &&
                    user.getLockTime().plusMinutes(lockoutDurationMinutes).isBefore(LocalDateTime.now())) {
                // Lockout window has elapsed - automatically unlock
                user.setAccountNonLocked(true);
                user.setFailedLoginAttempts(0);
                user.setLockTime(null);
                userRepository.save(user);
            } else {
                throw new AccountLockedException(
                        "This account is temporarily locked due to multiple failed login attempts. " +
                                "Please try again later or reset your password.");
            }
        }
    }

    private void registerFailedAttempt(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= maxFailedAttempts) {
            user.setAccountNonLocked(false);
            user.setLockTime(LocalDateTime.now());
            emailService.sendAccountLockedEmail(user.getEmail());
            auditService.log(user, "ACCOUNT_LOCKED", "User", user.getId().toString(),
                    "Locked after " + attempts + " failed login attempts", AuditService.Status.FAILURE);
        } else {
            auditService.log(user, "LOGIN_FAILED", "User", user.getId().toString(),
                    "Failed login attempt " + attempts + " of " + maxFailedAttempts, AuditService.Status.FAILURE);
        }

        userRepository.save(user);
    }

    private void resetFailedAttempts(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
        }
    }
}
