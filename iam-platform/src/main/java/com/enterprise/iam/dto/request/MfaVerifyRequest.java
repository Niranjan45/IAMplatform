package com.enterprise.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record MfaVerifyRequest(
        @NotBlank @Pattern(regexp = "^[0-9]{6}$", message = "OTP must be a 6-digit code") String code
) {
}
