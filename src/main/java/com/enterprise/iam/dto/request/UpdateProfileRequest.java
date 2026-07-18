package com.enterprise.iam.dto.request;

import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
        @Size(max = 60) String firstName,
        @Size(max = 60) String lastName,
        @Size(max = 20) String phoneNumber
) {
}
