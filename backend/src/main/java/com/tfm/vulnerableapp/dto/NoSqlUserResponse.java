package com.tfm.vulnerableapp.dto;

public record NoSqlUserResponse(
    String id,
    String username,
    String email,
    String role
) {
}
