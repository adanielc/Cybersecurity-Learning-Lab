package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.SqlInjectionUserResponse;
import com.tfm.vulnerableapp.service.SqlInjectionLabService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
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

    @GetMapping("/users/search-mode")
    public List<SqlInjectionUserResponse> searchByMode(@RequestParam(defaultValue = "") String username) {
        return service.searchByMode(username);
    }
}
