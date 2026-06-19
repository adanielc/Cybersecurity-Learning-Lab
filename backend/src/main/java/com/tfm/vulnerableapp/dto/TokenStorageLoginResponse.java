package com.tfm.vulnerableapp.dto;

import java.time.Instant;

public record TokenStorageLoginResponse(
        String accessToken,
        String tokenType,
        String algorithm,
        String tokenPurpose,
        String storageAdvice,
        boolean cookieAvailable,
        Instant expiresAt,
        TokenStorageUserDto user
) {
}
