package com.tfm.vulnerableapp.dto;

import java.util.List;
import java.util.Map;

public record SeedDataDatasetResponse(
    String name,
    String kind,
    int rowCount,
    List<String> columns,
    List<String> indexes,
    List<Map<String, Object>> rows
) {
}
