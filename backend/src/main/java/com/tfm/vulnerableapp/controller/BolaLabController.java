package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.UserProfileDto;
import com.tfm.vulnerableapp.service.BolaLabService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lab/bola")
public class BolaLabController {

    private final BolaLabService bolaLabService;

    public BolaLabController(BolaLabService bolaLabService) {
        this.bolaLabService = bolaLabService;
    }

    @GetMapping("/profile/{userId}")
    public ResponseEntity<UserProfileDto> vulnerableProfile(@PathVariable Long userId) {
        return ResponseEntity.ok(bolaLabService.getProfileVulnerable(userId));
    }

    @GetMapping("/profile-secure/{userId}")
    public ResponseEntity<UserProfileDto> secureProfile(@PathVariable Long userId) {
        return ResponseEntity.ok(bolaLabService.getProfileSecure(userId));
    }

    @GetMapping("/my-profile")
    public ResponseEntity<UserProfileDto> myProfile() {
        return ResponseEntity.ok(bolaLabService.getCurrentUserProfileSecure());
    }
}
