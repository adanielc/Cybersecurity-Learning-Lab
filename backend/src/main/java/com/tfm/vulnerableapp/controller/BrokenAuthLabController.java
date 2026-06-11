package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.AuthResponse;
import com.tfm.vulnerableapp.dto.LoginRequest;
import com.tfm.vulnerableapp.dto.RegisterRequest;
import com.tfm.vulnerableapp.service.BrokenAuthLabService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lab/auth")
public class BrokenAuthLabController {

    private final BrokenAuthLabService brokenAuthLabService;

    public BrokenAuthLabController(BrokenAuthLabService brokenAuthLabService) {
        this.brokenAuthLabService = brokenAuthLabService;
    }

    @PostMapping("/login-insecure")
    public AuthResponse loginInsecure(@Valid @RequestBody LoginRequest request) {
        return brokenAuthLabService.loginInsecure(request);
    }

    @PostMapping("/login-secure")
    public AuthResponse loginSecure(@Valid @RequestBody LoginRequest request, HttpServletRequest httpServletRequest) {
        return brokenAuthLabService.loginSecure(request, httpServletRequest.getRemoteAddr());
    }

    @PostMapping("/register-insecure")
    public AuthResponse registerInsecure(@Valid @RequestBody RegisterRequest request) {
        return brokenAuthLabService.registerInsecure(request);
    }

    @PostMapping("/register-secure")
    public AuthResponse registerSecure(@Valid @RequestBody RegisterRequest request) {
        return brokenAuthLabService.registerSecure(request);
    }
}
