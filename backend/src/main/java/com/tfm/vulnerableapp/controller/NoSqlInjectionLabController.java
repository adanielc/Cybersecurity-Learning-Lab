package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.NoSqlCommentResponse;
import com.tfm.vulnerableapp.dto.NoSqlCommentSearchRequest;
import com.tfm.vulnerableapp.dto.NoSqlLoginRequest;
import com.tfm.vulnerableapp.dto.NoSqlLoginResponse;
import com.tfm.vulnerableapp.service.NoSqlInjectionLabService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/lab/nosqli")
public class NoSqlInjectionLabController {

    private final NoSqlInjectionLabService noSqlInjectionLabService;

    public NoSqlInjectionLabController(NoSqlInjectionLabService noSqlInjectionLabService) {
        this.noSqlInjectionLabService = noSqlInjectionLabService;
    }

    @PostMapping("/login")
    public NoSqlLoginResponse loginVulnerable(
        @RequestBody(required = false) Map<String, Object> body
    ) {
        return noSqlInjectionLabService.loginVulnerable(body);
    }

    @PostMapping("/login-secure")
    public NoSqlLoginResponse loginSecure(
        @Valid @RequestBody NoSqlLoginRequest request
    ) {
        return noSqlInjectionLabService.loginSecure(request);
    }

    @PostMapping("/search-comments")
    public List<NoSqlCommentResponse> searchCommentsVulnerable(
        @RequestBody(required = false) Map<String, Object> body
    ) {
        return noSqlInjectionLabService.searchCommentsVulnerable(body);
    }

    @PostMapping("/search-comments-secure")
    public List<NoSqlCommentResponse> searchCommentsSecure(
        @Valid @RequestBody NoSqlCommentSearchRequest request
    ) {
        return noSqlInjectionLabService.searchCommentsSecure(request);
    }
}
