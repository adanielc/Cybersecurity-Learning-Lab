package com.tfm.vulnerableapp.dto;

public record TokenStorageUserDto(
        Long id,
        String username,
        String displayName,
        String role
) {
}
