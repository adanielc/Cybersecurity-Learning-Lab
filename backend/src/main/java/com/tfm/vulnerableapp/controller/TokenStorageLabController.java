package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.TokenStorageLoginRequest;
import com.tfm.vulnerableapp.dto.TokenStorageLoginResponse;
import com.tfm.vulnerableapp.dto.TokenStorageMeResponse;
import com.tfm.vulnerableapp.service.TokenStorageLabService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lab/token-storage")
public class TokenStorageLabController {

    private final TokenStorageLabService tokenStorageLabService;

    public TokenStorageLabController(TokenStorageLabService tokenStorageLabService) {
        this.tokenStorageLabService = tokenStorageLabService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenStorageLoginResponse> login(@Valid @RequestBody TokenStorageLoginRequest request) {
        var loginResult = tokenStorageLabService.login(request);
        TokenStorageLoginResponse response = loginResult.response();
        ResponseEntity.BodyBuilder builder = ResponseEntity.ok();

        if (response.cookieAvailable()) {
            ResponseCookie cookie = ResponseCookie.from(tokenStorageLabService.cookieName(), loginResult.rawToken())
                    .httpOnly(true)
                    .sameSite("Lax")
                    .secure(false)
                    .path("/")
                    .maxAge(30 * 60)
                    .build();
            builder.header(HttpHeaders.SET_COOKIE, cookie.toString());
        }

        return builder.body(response);
    }

    @GetMapping("/me")
    public TokenStorageMeResponse me(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @CookieValue(value = "TFM_ACCESS_TOKEN", required = false) String cookieToken
    ) {
        return tokenStorageLabService.me(authorizationHeader, cookieToken);
    }
}
