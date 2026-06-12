package com.tfm.vulnerableapp.dto;

public record CorsLabResponseDto(
    String endpoint,
    String mode,
    String policy,
    String title,
    String message,
    String sampleData
) {
}
