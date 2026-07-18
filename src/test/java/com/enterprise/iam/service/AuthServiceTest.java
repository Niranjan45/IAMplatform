package com.enterprise.iam.service;

import com.enterprise.iam.dto.request.LoginRequest;
import com.enterprise.iam.dto.request.RegisterRequest;
import com.enterprise.iam.dto.response.AuthResponse;
import com.enterprise.iam.entity.*;
import com.enterprise.iam.exception.AccountLockedException;
import com.enterprise.iam.exception.DuplicateResourceException;
import com.enterprise.iam.exception.InvalidCredentialsException;
import com.enterprise.iam.repository.*;
import com.enterprise.iam.security.JwtService;
import com.enterprise.iam.util.RandomTokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Mock private PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private TokenService tokenService;
    @Mock private MfaService mfaService;
    @Mock private EmailService emailService;
    @Mock private AuditService auditService;
    @Mock private RandomTokenGenerator tokenGenerator;

    @InjectMocks
    private AuthService authService;

    private Role defaultRole;
    private User testUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "maxFailedAttempts", 5);
        ReflectionTestUtils.setField(authService, "lockoutDurationMinutes", 30L);
        ReflectionTestUtils.setField(authService, "passwordResetExpirationMinutes", 30L);
        ReflectionTestUtils.setField(authService, "emailVerificationExpirationHours", 24L);

        defaultRole = Role.builder().id(1L).name("ROLE_USER").permissions(Set.of()).build();

        testUser = User.builder()
                .id(1L)
                .email("jdoe@example.com")
                .username("jdoe")
                .passwordHash("encoded-password")
                .enabled(true)
                .emailVerified(true)
                .accountNonLocked(true)
                .mfaEnabled(false)
                .failedLoginAttempts(0)
                .roles(Set.of(defaultRole))
                .build();
    }

    @Test
    void register_shouldThrowWhenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest("jdoe@example.com", "jdoe", "Password1!", "John", "Doe", null);
        when(userRepository.existsByEmail(request.email())).thenReturn(true);

        assertThrows(DuplicateResourceException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_shouldThrowWhenUsernameAlreadyExists() {
        RegisterRequest request = new RegisterRequest("new@example.com", "jdoe", "Password1!", "John", "Doe", null);
        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(userRepository.existsByUsername(request.username())).thenReturn(true);

        assertThrows(DuplicateResourceException.class, () -> authService.register(request));
    }

    @Test
    void register_shouldCreateUserWithDefaultRoleAndSendVerificationEmail() {
        RegisterRequest request = new RegisterRequest("new@example.com", "newuser", "Password1!", "John", "Doe", null);
        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(userRepository.existsByUsername(request.username())).thenReturn(false);
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(defaultRole));
        when(passwordEncoder.encode(request.password())).thenReturn("encoded");
        when(tokenGenerator.generate(32)).thenReturn("verification-token");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(2L);
            return u;
        });

        authService.register(request);

        verify(emailService).sendVerificationEmail(eq("new@example.com"), eq("verification-token"));
        verify(emailVerificationTokenRepository).save(any(EmailVerificationToken.class));
    }

    @Test
    void login_shouldThrowInvalidCredentialsWhenUserNotFound() {
        LoginRequest request = new LoginRequest("nobody", "password", null);
        when(userRepository.findByEmailOrUsername("nobody", "nobody")).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, "test-agent"));
    }

    @Test
    void login_shouldThrowWhenAccountIsLocked() {
        testUser.setAccountNonLocked(false);
        testUser.setLockTime(LocalDateTime.now());

        LoginRequest request = new LoginRequest("jdoe", "password", null);
        when(userRepository.findByEmailOrUsername("jdoe", "jdoe")).thenReturn(Optional.of(testUser));

        assertThrows(AccountLockedException.class, () -> authService.login(request, "test-agent"));
    }

    @Test
    void login_shouldThrowInvalidCredentialsOnWrongPassword() {
        LoginRequest request = new LoginRequest("jdoe", "wrong-password", null);
        when(userRepository.findByEmailOrUsername("jdoe", "jdoe")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong-password", testUser.getPasswordHash())).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, "test-agent"));
        assertEquals(1, testUser.getFailedLoginAttempts());
    }

    @Test
    void login_shouldLockAccountAfterMaxFailedAttempts() {
        testUser.setFailedLoginAttempts(4); // one more failure should trigger lockout
        LoginRequest request = new LoginRequest("jdoe", "wrong-password", null);
        when(userRepository.findByEmailOrUsername("jdoe", "jdoe")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong-password", testUser.getPasswordHash())).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(request, "test-agent"));

        assertFalse(testUser.isAccountNonLocked());
        assertNotNull(testUser.getLockTime());
        verify(emailService).sendAccountLockedEmail(testUser.getEmail());
    }

    @Test
    void login_shouldReturnMfaRequiredWhenMfaEnabledAndNoOtpProvided() {
        testUser.setMfaEnabled(true);
        LoginRequest request = new LoginRequest("jdoe", "password", null);
        when(userRepository.findByEmailOrUsername("jdoe", "jdoe")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password", testUser.getPasswordHash())).thenReturn(true);

        AuthResponse response = authService.login(request, "test-agent");

        assertTrue(response.mfaRequired());
        assertNull(response.accessToken());
    }

    @Test
    void login_shouldSucceedWithCorrectCredentials() {
        LoginRequest request = new LoginRequest("jdoe", "password", null);
        RefreshToken refreshToken = RefreshToken.builder().token("refresh-token-value").user(testUser).build();

        when(userRepository.findByEmailOrUsername("jdoe", "jdoe")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password", testUser.getPasswordHash())).thenReturn(true);
        when(jwtService.generateAccessToken(any())).thenReturn("access-token-value");
        when(jwtService.getAccessTokenExpirationMs()).thenReturn(900_000L);
        when(tokenService.issueRefreshToken(eq(testUser), any())).thenReturn(refreshToken);

        AuthResponse response = authService.login(request, "test-agent");

        assertFalse(response.mfaRequired());
        assertEquals("access-token-value", response.accessToken());
        assertEquals("refresh-token-value", response.refreshToken());
        assertEquals(0, testUser.getFailedLoginAttempts());
    }
}
