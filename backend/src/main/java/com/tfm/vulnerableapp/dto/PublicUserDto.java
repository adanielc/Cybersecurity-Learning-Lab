package com.tfm.vulnerableapp.dto;

public record PublicUserDto(
    Long id,
    String username,
    String visibleName
) {
}
