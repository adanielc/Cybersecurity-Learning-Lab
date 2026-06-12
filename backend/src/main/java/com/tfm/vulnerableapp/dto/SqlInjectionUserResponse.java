package com.tfm.vulnerableapp.dto;

public record SqlInjectionUserResponse(
        Long id,
        String username,
        String email,
        String role
) {
}
