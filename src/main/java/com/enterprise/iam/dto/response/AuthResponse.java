

package com.enterprise.iam.dto.response;

public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    long expiresIn,
    boolean mfaRequired, // Implicitly creates: public boolean mfaRequired()
    UserResponse user
) {
    // Static factory method for a successful login response
    public static AuthResponse of(String accessToken, String refreshToken, long expiresIn, UserResponse user) {
        return new AuthResponse(accessToken, refreshToken, "Bearer", expiresIn, false, user);
    }

    // Renamed to avoid clashing with the automatic getter method
    public static AuthResponse ofMfaRequired() {
        return new AuthResponse(null, null, null, 0, true, null);
    }
}