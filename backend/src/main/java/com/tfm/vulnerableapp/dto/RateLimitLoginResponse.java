package com.tfm.vulnerableapp.dto;

public record RateLimitLoginResponse(
    boolean success,
    String message,
    int failedAttempts,
    int remainingAttempts
) {
}
