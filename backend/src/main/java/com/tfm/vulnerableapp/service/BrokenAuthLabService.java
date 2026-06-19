package com.tfm.vulnerableapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tfm.vulnerableapp.config.LabSecurityProperties;
import com.tfm.vulnerableapp.dto.AuthResponse;
import com.tfm.vulnerableapp.dto.LoginRequest;
import com.tfm.vulnerableapp.dto.RegisterRequest;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class BrokenAuthLabService {

    private static final String JWT_PURPOSE = "broken-auth-lab";
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long FAILURE_WINDOW_SECONDS = 60;

    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder;
    private final LabSecurityProperties labSecurityProperties;

    private final Map<String, InsecureUser> insecureUsers = new LinkedHashMap<>();
    private final Map<String, SecureUser> secureUsers = new LinkedHashMap<>();
    private final ConcurrentMap<String, Deque<Instant>> secureFailures = new ConcurrentHashMap<>();

    public BrokenAuthLabService(ObjectMapper objectMapper,
                                PasswordEncoder passwordEncoder,
                                LabSecurityProperties labSecurityProperties) {
        this.objectMapper = objectMapper;
        this.passwordEncoder = passwordEncoder;
        this.labSecurityProperties = labSecurityProperties;
    }

    @PostConstruct
    public void seedUsers() {
        if (!insecureUsers.isEmpty()) {
            return;
        }

        registerSeed("admin", "admin@example.com", "Admin TFM", "ADMIN", "admin123");
        registerSeed("alice", "alice@example.com", "Alice Labs", "USER", "password123");
        registerSeed("bob", "bob@example.com", "Bob Labs", "USER", "password123");
        registerSeed("auditor", "auditor@example.com", "Auditor Labs", "AUDITOR", "audit123");
    }

    public AuthResponse loginInsecure(LoginRequest request) {
        // Vulnerable: muestra si el usuario existe y si la contrasena es incorrecta.
        InsecureUser user = insecureUsers.get(normalize(request.username()));
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuario no encontrado");
        }

        if (!Objects.equals(user.password(), request.password())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Contraseña incorrecta");
        }

        return buildResponse(user.username(), user.email(), user.displayName(), user.role(), issuedToken(user.username(), user.role()));
    }

    public AuthResponse loginSecure(LoginRequest request, String clientKey) {
        String key = secureKey(request.username(), clientKey);
        if (isRateLimited(key)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos. Intenta de nuevo más tarde.");
        }

        SecureUser user = secureUsers.get(normalize(request.username()));
        boolean valid = user != null && passwordEncoder.matches(request.password(), user.passwordHash());
        if (!valid) {
            registerFailure(key);
            // Seguro: mensaje genérico para evitar enumeracion de usuarios.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        secureFailures.remove(key);
        return buildResponse(user.username(), user.email(), user.displayName(), user.role(), issuedToken(user.username(), user.role()));
    }

    public AuthResponse registerInsecure(RegisterRequest request) {
        // Vulnerable: permite contrasenas debiles y revela si el usuario ya existe.
        String normalized = normalize(request.username());
        if (insecureUsers.containsKey(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El usuario ya existe");
        }

        insecureUsers.put(normalized, new InsecureUser(
                request.username(),
                request.email(),
                request.displayName(),
                "USER",
                request.password()
        ));

        return buildResponse(request.username(), request.email(), request.displayName(), "USER", issuedToken(request.username(), "USER"));
    }

    public AuthResponse registerSecure(RegisterRequest request) {
        if (!strongPassword(request.password())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo completar el registro");
        }

        String normalized = normalize(request.username());
        if (secureUsers.containsKey(normalized)) {
            // Seguro: no revela si el usuario existe o si fallo la politica.
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se pudo completar el registro");
        }

        secureUsers.put(normalized, new SecureUser(
                request.username(),
                request.email(),
                request.displayName(),
                "USER",
                passwordEncoder.encode(request.password())
        ));

        return buildResponse(request.username(), request.email(), request.displayName(), "USER", issuedToken(request.username(), "USER"));
    }

    private void registerSeed(String username, String email, String displayName, String role, String password) {
        insecureUsers.put(normalize(username), new InsecureUser(username, email, displayName, role, password));
        secureUsers.put(normalize(username), new SecureUser(username, email, displayName, role, passwordEncoder.encode(password)));
    }

    private boolean strongPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char ch : password.toCharArray()) {
            if (Character.isUpperCase(ch)) {
                hasUpper = true;
            } else if (Character.isLowerCase(ch)) {
                hasLower = true;
            } else if (Character.isDigit(ch)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    private boolean isRateLimited(String key) {
        Deque<Instant> attempts = secureFailures.get(key);
        if (attempts == null) {
            return false;
        }

        prune(attempts);
        return attempts.size() >= MAX_FAILED_ATTEMPTS;
    }

    private void registerFailure(String key) {
        Deque<Instant> attempts = secureFailures.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (attempts) {
            prune(attempts);
            attempts.addLast(Instant.now());
        }
    }

    private void prune(Deque<Instant> attempts) {
        Instant cutoff = Instant.now().minusSeconds(FAILURE_WINDOW_SECONDS);
        while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) {
            attempts.removeFirst();
        }
    }

    private String secureKey(String username, String clientKey) {
        return normalize(username) + "|" + (clientKey == null ? "unknown" : clientKey);
    }

    private AuthResponse buildResponse(String username, String email, String displayName, String role, String token) {
        return new AuthResponse(
                true,
                "Operación completada correctamente",
                token,
                username,
                email,
                displayName,
                role,
                Instant.now().plus(30, ChronoUnit.MINUTES)
        );
    }

    private String issuedToken(String username, String role) {
        Map<String, Object> header = Map.of(
                "alg", "HS256",
                "typ", "JWT"
        );

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", normalize(username));
        payload.put("username", username);
        payload.put("role", role);
        payload.put("purpose", JWT_PURPOSE);
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", Instant.now().plus(30, ChronoUnit.MINUTES).getEpochSecond());

        try {
            String encodedHeader = base64Url(objectMapper.writeValueAsBytes(header));
            String encodedPayload = base64Url(objectMapper.writeValueAsBytes(payload));
            String unsignedToken = encodedHeader + "." + encodedPayload;
            return unsignedToken + "." + sign(unsignedToken);
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo crear el token", ex);
        }
    }

    private String sign(String unsignedToken) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(labSecurityProperties.jwt().secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return base64Url(mac.doFinal(unsignedToken.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo firmar el token", ex);
        }
    }

    private String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase();
    }

    private record InsecureUser(String username, String email, String displayName, String role, String password) {
    }

    private record SecureUser(String username, String email, String displayName, String role, String passwordHash) {
    }
}
