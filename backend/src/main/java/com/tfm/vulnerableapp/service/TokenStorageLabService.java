package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.config.SecurityModeProperties;
import com.tfm.vulnerableapp.dto.TokenStorageLoginRequest;
import com.tfm.vulnerableapp.dto.TokenStorageLoginResponse;
import com.tfm.vulnerableapp.dto.TokenStorageMeResponse;
import com.tfm.vulnerableapp.dto.TokenStorageUserDto;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TokenStorageLabService {

    private static final String JWT_PURPOSE = "token-storage-lab";
    private static final String COOKIE_NAME = "TFM_ACCESS_TOKEN";
    private static final DurationHolder TOKEN_TTL = new DurationHolder(30);
    private static final Pattern JSON_STRING_FIELD = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
    private static final Pattern JSON_NUMBER_FIELD = Pattern.compile("\"([^\"]+)\"\\s*:\\s*([0-9]+)");

    private final PasswordEncoder passwordEncoder;
    private final SecurityModeProperties securityModeProperties;
    private final Map<String, LabAccount> accounts = new LinkedHashMap<>();

    public TokenStorageLabService(PasswordEncoder passwordEncoder,
                                  SecurityModeProperties securityModeProperties) {
        this.passwordEncoder = passwordEncoder;
        this.securityModeProperties = securityModeProperties;
    }

    @PostConstruct
    public void seedAccounts() {
        if (!accounts.isEmpty()) {
            return;
        }

        register(1L, "admin", "Admin TFM", "ADMIN", "adminpass");
        register(2L, "alice", "Alice Labs", "USER", "password123");
        register(3L, "bob", "Bob Labs", "USER", "password123");
        register(4L, "auditor", "Auditor Labs", "AUDITOR", "auditpass");
    }

    public LoginResult login(TokenStorageLoginRequest request) {
        LabAccount account = authenticate(request.username(), request.password());
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(TOKEN_TTL.minutes, ChronoUnit.MINUTES);
        String deliveryMode = request.deliveryMode() == null ? "header" : request.deliveryMode().trim().toLowerCase();
        String token = createJwt(account, issuedAt, expiresAt);
        boolean cookieMode = "cookie".equals(deliveryMode);

        TokenStorageLoginResponse response = new TokenStorageLoginResponse(
                cookieMode ? null : token,
                "Bearer",
                "HS256",
                securityModeProperties.mode().name(),
                "JWT access token for the laboratory",
                "Store it in memory or send it via HttpOnly cookie. localStorage increases the impact of XSS.",
                cookieMode,
                expiresAt,
                account.toDto()
        );

        return new LoginResult(response, token);
    }

    public TokenStorageMeResponse me(String authorizationHeader, String cookieToken) {
        ResolvedToken resolvedToken = extractToken(authorizationHeader, cookieToken);
        DecodedToken decoded = verifyAndDecode(resolvedToken.token());
        LabAccount account = accounts.get(decoded.username());

        if (account == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuario no encontrado");
        }

        return new TokenStorageMeResponse(
                account.toDto(),
                resolvedToken.source(),
                "JWT access token for the laboratory",
                decoded.expiresAt()
        );
    }

    public String cookieName() {
        return COOKIE_NAME;
    }

    private LabAccount authenticate(String username, String password) {
        LabAccount account = accounts.get(normalize(username));

        if (account == null || !passwordEncoder.matches(password, account.passwordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        return account;
    }

    private String createJwt(LabAccount account, Instant issuedAt, Instant expiresAt) {
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"sub\":\"" + escapeJson(account.username()) + "\","
                + "\"uid\":" + account.id() + ","
                + "\"username\":\"" + escapeJson(account.username()) + "\","
                + "\"name\":\"" + escapeJson(account.displayName()) + "\","
                + "\"role\":\"" + escapeJson(account.role()) + "\","
                + "\"purpose\":\"" + JWT_PURPOSE + "\","
                + "\"mode\":\"" + securityModeProperties.mode().name() + "\","
                + "\"iat\":" + issuedAt.getEpochSecond() + ","
                + "\"exp\":" + expiresAt.getEpochSecond()
                + "}";

        String encodedHeader = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
        String unsignedToken = encodedHeader + "." + encodedPayload;
        return unsignedToken + "." + sign(unsignedToken);
    }

    private DecodedToken verifyAndDecode(String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Falta el token");
        }

        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT inválido");
            }

            String unsignedToken = parts[0] + "." + parts[1];
            String expectedSignature = sign(unsignedToken);
            if (!MessageDigest.isEqual(expectedSignature.getBytes(StandardCharsets.UTF_8), parts[2].getBytes(StandardCharsets.UTF_8))) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Firma JWT inválida");
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            long exp = longField(payloadJson, "exp");
            if (Instant.now().getEpochSecond() > exp) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT expirado");
            }

            String purpose = stringField(payloadJson, "purpose");
            if (!JWT_PURPOSE.equals(purpose)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Propósito del token no válido para este laboratorio");
            }

            String username = stringField(payloadJson, "username");
            return new DecodedToken(username, Instant.ofEpochSecond(exp));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT inválido", ex);
        }
    }

    private ResolvedToken extractToken(String authorizationHeader, String cookieToken) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return new ResolvedToken(authorizationHeader.substring("Bearer ".length()).trim(), "authorization-header");
        }

        if (cookieToken != null && !cookieToken.isBlank()) {
            return new ResolvedToken(cookieToken.trim(), "cookie(HttpOnly)");
        }

        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No se encontró token");
    }

    private String sign(String unsignedToken) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(securityModeProperties.jwt().secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return base64Url(mac.doFinal(unsignedToken.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo firmar el JWT", ex);
        }
    }

    private String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private long longField(String json, String field) {
        Matcher matcher = JSON_NUMBER_FIELD.matcher(json);
        while (matcher.find()) {
            if (field.equals(matcher.group(1))) {
                try {
                    return Long.parseLong(matcher.group(2));
                } catch (NumberFormatException ex) {
                    break;
                }
            }
        }

        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT inválido");
    }

    private String stringField(String json, String field) {
        Matcher matcher = JSON_STRING_FIELD.matcher(json);
        while (matcher.find()) {
            if (field.equals(matcher.group(1))) {
                return unescapeJson(matcher.group(2));
            }
        }

        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT inválido");
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    private String unescapeJson(String value) {
        if (value == null) {
            return "";
        }

        return value
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private void validateJwtField(boolean condition) {
        if (!condition) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "JWT inválido");
        }
    }

    private void register(Long id, String username, String displayName, String role, String password) {
        accounts.put(normalize(username), new LabAccount(id, username, displayName, role, passwordEncoder.encode(password)));
    }

    private String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase();
    }

    private record LabAccount(Long id, String username, String displayName, String role, String passwordHash) {
        private TokenStorageUserDto toDto() {
            return new TokenStorageUserDto(id, username, displayName, role);
        }
    }

    private record ResolvedToken(String token, String source) {
    }

    private record DecodedToken(String username, Instant expiresAt) {
    }

    public record LoginResult(TokenStorageLoginResponse response, String rawToken) {
    }

    private static final class DurationHolder {
        private final long minutes;

        private DurationHolder(long minutes) {
            this.minutes = minutes;
        }
    }
}
