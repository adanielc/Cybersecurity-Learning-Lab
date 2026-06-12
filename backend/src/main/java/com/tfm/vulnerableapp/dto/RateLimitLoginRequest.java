package com.tfm.vulnerableapp.dto;

public record RateLimitLoginRequest(
    String username,
    String password
) {
}
