package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.config.SecurityModeProperties;
import com.tfm.vulnerableapp.dto.RateLimitLoginRequest;
import com.tfm.vulnerableapp.dto.RateLimitLoginResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitLabService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final SecurityModeProperties securityModeProperties;
    private final Map<String, Deque<Instant>> failedAttemptsByKey = new ConcurrentHashMap<>();

    public RateLimitLabService(SecurityModeProperties securityModeProperties) {
        this.securityModeProperties = securityModeProperties;
    }

    public RateLimitLoginResponse loginInsecure(RateLimitLoginRequest request, String clientIp) {
        /*
         * VULNERABLE: no hay rate limiting. El endpoint acepta intentos ilimitados
         * y un atacante puede automatizar fuerza bruta sin freno.
         */
        boolean success = isValidCredentials(request);
        if (success) {
            return new RateLimitLoginResponse(true, "Login correcto", 0, MAX_FAILED_ATTEMPTS);
        }

        System.out.println("[RateLimitLab][INSECURE] intento fallido desde " + clientIp + " para username=" + normalize(request.username()));
        return new RateLimitLoginResponse(false, "Credenciales invalidas", 0, MAX_FAILED_ATTEMPTS);
    }

    public RateLimitLoginResponse loginSecure(RateLimitLoginRequest request, String clientIp) {
        String username = normalize(request.username());
        String bucketKey = buildKey(clientIp, username);
        Deque<Instant> failures = failedAttemptsByKey.computeIfAbsent(bucketKey, key -> new ArrayDeque<>());
        pruneWindow(failures);

        if (failures.size() >= MAX_FAILED_ATTEMPTS) {
            /*
             * SECURE: se corta el abuso temporalmente con HTTP 429.
             * No es un bloqueo permanente: la ventana expira sola.
             */
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos. Espera un minuto e intenta de nuevo.");
        }

        boolean success = isValidCredentials(request);
        if (success) {
            failures.clear();
            return new RateLimitLoginResponse(true, "Login correcto", 0, MAX_FAILED_ATTEMPTS);
        }

        failures.addLast(Instant.now());
        pruneWindow(failures);

        int failedAttempts = failures.size();
        int remainingAttempts = Math.max(0, MAX_FAILED_ATTEMPTS - failedAttempts);

        System.out.println("[RateLimitLab][SECURE] intento fallido desde " + clientIp + " para username=" + username + " (" + failedAttempts + "/" + MAX_FAILED_ATTEMPTS + ")");

        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos. Espera un minuto e intenta de nuevo.");
        }

        return new RateLimitLoginResponse(false, "Credenciales invalidas", failedAttempts, remainingAttempts);
    }

    private boolean isValidCredentials(RateLimitLoginRequest request) {
        String username = normalize(request.username());
        String password = normalize(request.password());
        return Objects.equals(username, "alice") && Objects.equals(password, "password123");
    }

    private void pruneWindow(Deque<Instant> failures) {
        Instant cutoff = Instant.now().minus(WINDOW);
        while (!failures.isEmpty() && failures.peekFirst().isBefore(cutoff)) {
            failures.removeFirst();
        }
    }

    private String buildKey(String clientIp, String username) {
        return normalize(clientIp) + "::" + username;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
