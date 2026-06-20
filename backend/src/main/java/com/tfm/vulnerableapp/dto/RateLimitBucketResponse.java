package com.tfm.vulnerableapp.dto;

public record RateLimitBucketResponse(
    String username,
    String clientIp,
    int failedAttempts,
    int remainingAttempts,
    int maxFailedAttempts,
    long windowSeconds,
    boolean limited
) {
}
