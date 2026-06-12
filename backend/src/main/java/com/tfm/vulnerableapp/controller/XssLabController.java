package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.CommentCreateRequest;
import com.tfm.vulnerableapp.dto.CommentDto;
import com.tfm.vulnerableapp.service.XssLabService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/lab/xss")
public class XssLabController {

    private final XssLabService xssLabService;

    public XssLabController(XssLabService xssLabService) {
        this.xssLabService = xssLabService;
    }

    @PostMapping("/comments")
    public ResponseEntity<CommentDto> createVulnerable(@Valid @RequestBody CommentCreateRequest request) {
        return ResponseEntity.ok(xssLabService.createVulnerable(request));
    }

    @GetMapping("/comments")
    public ResponseEntity<List<CommentDto>> listVulnerable() {
        return ResponseEntity.ok(xssLabService.listVulnerable());
    }

    @PostMapping("/comments-secure")
    public ResponseEntity<CommentDto> createSecure(@Valid @RequestBody CommentCreateRequest request) {
        return ResponseEntity.ok(xssLabService.createSecure(request));
    }

    @GetMapping("/comments-secure")
    public ResponseEntity<List<CommentDto>> listSecure() {
        return ResponseEntity.ok(xssLabService.listSecure());
    }
}
