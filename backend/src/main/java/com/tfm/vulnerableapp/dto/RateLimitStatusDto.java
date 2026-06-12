package com.tfm.vulnerableapp.dto;

public record RateLimitStatusDto(
    String mode,
    int maxFailedAttemptsPerMinute,
    String window,
    String note
) {
}
