package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.dto.RateLimitBucketEntryResponse;
import com.tfm.vulnerableapp.dto.RateLimitBucketResponse;
import com.tfm.vulnerableapp.dto.RateLimitLoginRequest;
import com.tfm.vulnerableapp.dto.RateLimitLoginResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitLabService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final Map<String, Deque<Instant>> failedAttemptsByKey = new ConcurrentHashMap<>();

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

    public RateLimitBucketResponse inspectBucket(String username, String clientIp) {
        String normalizedUsername = normalize(username);
        String normalizedIp = normalize(clientIp);
        return buildBucketResponse(normalizedUsername, normalizedIp);
    }

    public RateLimitBucketResponse resetBucket(String username, String clientIp) {
        String normalizedUsername = normalize(username);
        String normalizedIp = normalize(clientIp);
        String bucketSuffix = bucketSuffix(normalizedUsername);

        failedAttemptsByKey.keySet().removeIf(key -> key.endsWith(bucketSuffix));

        return buildBucketResponse(normalizedUsername, normalizedIp);
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

    private RateLimitBucketResponse buildBucketResponse(String username, String clientIp) {
        List<RateLimitBucketEntryResponse> activeBuckets = activeBucketsForUsername(username);
        String currentBucketKey = buildKey(clientIp, username);

        RateLimitBucketEntryResponse currentBucket = activeBuckets.stream()
            .filter(bucket -> bucket.bucketKey().equals(currentBucketKey))
            .findFirst()
            .orElse(null);

        int failedAttempts = currentBucket == null ? 0 : currentBucket.failedAttempts();
        int remainingAttempts = currentBucket == null ? MAX_FAILED_ATTEMPTS : currentBucket.remainingAttempts();
        boolean limited = currentBucket != null && currentBucket.limited();

        return new RateLimitBucketResponse(
            username,
            clientIp,
            failedAttempts,
            remainingAttempts,
            MAX_FAILED_ATTEMPTS,
            WINDOW.toSeconds(),
            limited,
            activeBuckets.size(),
            activeBuckets
        );
    }

    private List<RateLimitBucketEntryResponse> activeBucketsForUsername(String username) {
        String bucketSuffix = bucketSuffix(username);
        List<RateLimitBucketEntryResponse> activeBuckets = new ArrayList<>();

        for (Map.Entry<String, Deque<Instant>> entry : failedAttemptsByKey.entrySet()) {
            String bucketKey = entry.getKey();
            if (!bucketKey.endsWith(bucketSuffix)) {
                continue;
            }

            Deque<Instant> failures = entry.getValue();
            pruneWindow(failures);

            if (failures.isEmpty()) {
                failedAttemptsByKey.remove(bucketKey, failures);
                continue;
            }

            String clientIp = bucketKey.substring(0, bucketKey.length() - bucketSuffix.length());
            int failedAttempts = failures.size();
            int remainingAttempts = Math.max(0, MAX_FAILED_ATTEMPTS - failedAttempts);

            activeBuckets.add(new RateLimitBucketEntryResponse(
                bucketKey,
                username,
                clientIp,
                failedAttempts,
                remainingAttempts,
                failedAttempts >= MAX_FAILED_ATTEMPTS,
                failures.stream().map(Instant::toString).toList()
            ));
        }

        activeBuckets.sort((left, right) -> left.clientIp().compareTo(right.clientIp()));
        return activeBuckets;
    }

    private String buildKey(String clientIp, String username) {
        return normalize(clientIp) + "::" + username;
    }

    private String bucketSuffix(String username) {
        return "::" + username;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
