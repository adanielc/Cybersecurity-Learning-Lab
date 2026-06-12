package com.tfm.vulnerableapp.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;

@JsonIgnoreProperties(ignoreUnknown = false)
public record NoSqlLoginRequest(
    @NotBlank String username,
    @NotBlank String password
) {
}
