package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.PublicUserDto;
import com.tfm.vulnerableapp.entity.DataExposureUserEntity;
import com.tfm.vulnerableapp.service.DataExposureLabService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/lab/exposure")
public class DataExposureLabController {

    private final DataExposureLabService dataExposureLabService;

    public DataExposureLabController(DataExposureLabService dataExposureLabService) {
        this.dataExposureLabService = dataExposureLabService;
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<DataExposureUserEntity> vulnerableUser(@PathVariable Long id) {
        return ResponseEntity.ok(dataExposureLabService.getUserVulnerable(id));
    }

    @GetMapping("/users-secure/{id}")
    public ResponseEntity<PublicUserDto> secureUser(@PathVariable Long id) {
        return ResponseEntity.ok(dataExposureLabService.getUserSecure(id));
    }

    @GetMapping("/users")
    public ResponseEntity<List<?>> vulnerableList() {
        return ResponseEntity.ok(dataExposureLabService.listUsersVulnerable());
    }

    @GetMapping("/users-secure")
    public ResponseEntity<List<PublicUserDto>> secureList() {
        return ResponseEntity.ok(dataExposureLabService.listUsersSecure());
    }
}
