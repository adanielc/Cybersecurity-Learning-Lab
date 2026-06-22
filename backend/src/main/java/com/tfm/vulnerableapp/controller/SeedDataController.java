package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.SeedDataOverviewResponse;
import com.tfm.vulnerableapp.service.SeedDataService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class SeedDataController {

    private final SeedDataService seedDataService;

    public SeedDataController(SeedDataService seedDataService) {
        this.seedDataService = seedDataService;
    }

    @GetMapping("/seed-data")
    public ResponseEntity<SeedDataOverviewResponse> readSeedData() {
        return ResponseEntity.ok(seedDataService.readOverview());
    }
}
