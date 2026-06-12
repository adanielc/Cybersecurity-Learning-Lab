package com.tfm.vulnerableapp.dto;

public record UserProfileDto(
    Long id,
    String username,
    String email,
    String role,
    String fullName,
    String department
) {
}
