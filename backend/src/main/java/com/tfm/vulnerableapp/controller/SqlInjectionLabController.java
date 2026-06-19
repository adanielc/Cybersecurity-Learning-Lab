package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.LoginRequest;
import com.tfm.vulnerableapp.dto.SqlInjectionLoginResponse;
import com.tfm.vulnerableapp.dto.SqlInjectionUserResponse;
import com.tfm.vulnerableapp.service.SqlInjectionLabService;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lab/sqli")
public class SqlInjectionLabController {

    private final SqlInjectionLabService service;

    public SqlInjectionLabController(SqlInjectionLabService service) {
        this.service = service;
    }

    @GetMapping("/users/search")
    public List<SqlInjectionUserResponse> searchVulnerable(@RequestParam(defaultValue = "") String username) {
        return service.searchVulnerable(username);
    }

    @GetMapping("/users/search-secure")
    public List<SqlInjectionUserResponse> searchSecure(@RequestParam(defaultValue = "") String username) {
        return service.searchSecure(username);
    }

    @PostMapping("/login")
    public SqlInjectionLoginResponse loginVulnerable(@Valid @RequestBody LoginRequest request) {
        return service.loginVulnerable(request);
    }

    @PostMapping("/login-secure")
    public SqlInjectionLoginResponse loginSecure(@Valid @RequestBody LoginRequest request) {
        return service.loginSecure(request);
    }
}
