package com.tfm.vulnerableapp.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenStorageLoginRequest(
        @NotBlank String username,
        @NotBlank String password,
        String deliveryMode
) {
}
