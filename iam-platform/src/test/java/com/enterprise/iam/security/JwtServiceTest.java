package com.enterprise.iam.security;

import com.enterprise.iam.entity.Role;
import com.enterprise.iam.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;
    private static final String TEST_SECRET = "dGVzdC1zZWNyZXQta2V5LWZvci11bml0LXRlc3RzLW9ubHktZG8tbm90LXVzZS1pbi1wcm9k";

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(TEST_SECRET, 900_000L, "test-issuer");
    }

    private SecurityUserDetails buildTestUser() {
        Role role = Role.builder().id(1L).name("ROLE_USER").permissions(Set.of()).build();
        User user = User.builder()
                .id(1L)
                .username("jdoe")
                .email("jdoe@example.com")
                .passwordHash("hashed")
                .enabled(true)
                .accountNonLocked(true)
                .roles(Set.of(role))
                .build();
        return new SecurityUserDetails(user);
    }

    @Test
    void generateAccessToken_shouldProduceValidToken() {
        SecurityUserDetails user = buildTestUser();
        String token = jwtService.generateAccessToken(user);

        assertNotNull(token);
        assertTrue(jwtService.isTokenValid(token, "jdoe"));
    }

    @Test
    void extractUsername_shouldReturnCorrectUsername() {
        SecurityUserDetails user = buildTestUser();
        String token = jwtService.generateAccessToken(user);

        assertEquals("jdoe", jwtService.extractUsername(token));
    }

    @Test
    void extractUserId_shouldReturnCorrectId() {
        SecurityUserDetails user = buildTestUser();
        String token = jwtService.generateAccessToken(user);

        assertEquals(1L, jwtService.extractUserId(token));
    }

    @Test
    void extractAuthorities_shouldContainRole() {
        SecurityUserDetails user = buildTestUser();
        String token = jwtService.generateAccessToken(user);

        assertTrue(jwtService.extractAuthorities(token).contains("ROLE_USER"));
    }

    @Test
    void isTokenValid_shouldReturnFalseForWrongUsername() {
        SecurityUserDetails user = buildTestUser();
        String token = jwtService.generateAccessToken(user);

        assertFalse(jwtService.isTokenValid(token, "someone-else"));
    }

    @Test
    void isTokenValid_shouldReturnFalseForMalformedToken() {
        assertFalse(jwtService.isTokenValid("not-a-real-token", "jdoe"));
    }

    @Test
    void generateAccessToken_expiredTokenShouldBeInvalid() {
        JwtService shortLivedJwtService = new JwtService(TEST_SECRET, -1000L, "test-issuer");
        SecurityUserDetails user = buildTestUser();
        String token = shortLivedJwtService.generateAccessToken(user);

        assertFalse(shortLivedJwtService.isTokenValid(token, "jdoe"));
    }
}
