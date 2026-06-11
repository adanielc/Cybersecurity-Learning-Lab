package com.tfm.vulnerableapp.dto;

import java.time.Instant;

public record TokenStorageMeResponse(
        TokenStorageUserDto user,
        String tokenSource,
        String tokenPurpose,
        Instant expiresAt
) {
}
