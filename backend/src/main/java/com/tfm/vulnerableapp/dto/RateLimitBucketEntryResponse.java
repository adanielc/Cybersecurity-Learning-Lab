package com.tfm.vulnerableapp.dto;

import java.util.List;

public record RateLimitBucketEntryResponse(
    String bucketKey,
    String username,
    String clientIp,
    int failedAttempts,
    int remainingAttempts,
    boolean limited,
    List<String> failureTimestamps
) {
}
