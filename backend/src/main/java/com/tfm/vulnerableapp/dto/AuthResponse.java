package com.tfm.vulnerableapp.dto;

import java.time.Instant;

public record AuthResponse(
        boolean success,
        String message,
        String token,
        String username,
        String email,
        String displayName,
        String role,
        Instant expiresAt
) {
}
