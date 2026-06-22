package com.tfm.vulnerableapp.dto;

import java.util.List;

public record RateLimitBucketResponse(
    String username,
    String clientIp,
    int failedAttempts,
    int remainingAttempts,
    int maxFailedAttempts,
    long windowSeconds,
    boolean limited,
    int trackedBuckets,
    List<RateLimitBucketEntryResponse> activeBuckets
) {
}
