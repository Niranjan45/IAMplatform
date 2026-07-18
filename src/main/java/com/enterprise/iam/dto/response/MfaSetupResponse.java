package com.enterprise.iam.dto.response;

public record MfaSetupResponse(
        String secret,
        String qrCodeDataUri,
        String otpAuthUrl
) {
}
