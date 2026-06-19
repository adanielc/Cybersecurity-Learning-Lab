package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.RateLimitBucketResponse;
import com.tfm.vulnerableapp.dto.RateLimitLoginRequest;
import com.tfm.vulnerableapp.dto.RateLimitLoginResponse;
import com.tfm.vulnerableapp.service.RateLimitLabService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/lab/rate-limit")
public class RateLimitLabController {

    private final RateLimitLabService rateLimitLabService;

    public RateLimitLabController(RateLimitLabService rateLimitLabService) {
        this.rateLimitLabService = rateLimitLabService;
    }

    @PostMapping("/login-insecure")
    public ResponseEntity<RateLimitLoginResponse> loginInsecure(
        @RequestBody RateLimitLoginRequest request,
        HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(rateLimitLabService.loginInsecure(request, clientIp(servletRequest)));
    }

    @PostMapping("/login-secure")
    public ResponseEntity<RateLimitLoginResponse> loginSecure(
        @RequestBody RateLimitLoginRequest request,
        HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(rateLimitLabService.loginSecure(request, clientIp(servletRequest)));
    }

    @GetMapping("/state")
    public ResponseEntity<RateLimitBucketResponse> state(
        @RequestParam String username,
        HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(rateLimitLabService.inspectBucket(username, clientIp(servletRequest)));
    }

    @PostMapping("/reset")
    public ResponseEntity<RateLimitBucketResponse> reset(
        @RequestParam String username,
        HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(rateLimitLabService.resetBucket(username, clientIp(servletRequest)));
    }


    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
