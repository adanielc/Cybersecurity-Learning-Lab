package com.tfm.vulnerableapp.dto;

import java.util.List;

public record SeedDataOverviewResponse(
    int sqlTableCount,
    int noSqlCollectionCount,
    int totalDatasets,
    List<SeedDataDatasetResponse> sqlTables,
    List<SeedDataDatasetResponse> noSqlCollections
) {
}
