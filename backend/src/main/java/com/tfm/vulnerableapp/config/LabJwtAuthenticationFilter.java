package com.tfm.vulnerableapp.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

@Component
public class LabJwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Set<String> VALID_PURPOSES = Set.of("token-storage-lab", "broken-auth-lab");

    private final ObjectMapper objectMapper;
    private final SecurityModeProperties securityModeProperties;

    public LabJwtAuthenticationFilter(ObjectMapper objectMapper, SecurityModeProperties securityModeProperties) {
        this.objectMapper = objectMapper;
        this.securityModeProperties = securityModeProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String authorization = request.getHeader("Authorization");
            if (authorization != null && authorization.startsWith("Bearer ")) {
                LabPrincipal principal = decodeAndValidate(authorization.substring("Bearer ".length()).trim());
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        principal.username(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + principal.role()))
                );
                authentication.setDetails(principal);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(request, response);
        } catch (ResponseStatusException ex) {
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
        } finally {
            if (!request.isAsyncStarted()) {
                SecurityContextHolder.clearContext();
            }
        }
    }

    private LabPrincipal decodeAndValidate(String token) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT inválido");
        }

        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT inválido");
            }

            String unsignedToken = parts[0] + "." + parts[1];
            String expectedSignature = sign(unsignedToken);
            if (!MessageDigest.isEqual(expectedSignature.getBytes(StandardCharsets.UTF_8), parts[2].getBytes(StandardCharsets.UTF_8))) {
                throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "Firma JWT inválida");
            }

            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode payload = objectMapper.readTree(payloadBytes);

            long exp = longNode(payload, "exp");
            if (System.currentTimeMillis() / 1000L > exp) {
                throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT expirado");
            }

            String purpose = textNode(payload, "purpose");
            if (!VALID_PURPOSES.contains(purpose)) {
                throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT no válido para el laboratorio");
            }

            String role = textNode(payload, "role").trim().toUpperCase();
            String username = textNode(payload, "username");
            return new LabPrincipal(username, role);
        } catch (IllegalArgumentException | IOException ex) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT inválido", ex);
        }
    }

    private String sign(String unsignedToken) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(securityModeProperties.jwt().secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(unsignedToken.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo validar el JWT", ex);
        }
    }

    private long longNode(JsonNode node, String field) {
        if (!node.hasNonNull(field) || !node.get(field).canConvertToLong()) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT inválido");
        }
        return node.get(field).asLong();
    }

    private String textNode(JsonNode node, String field) {
        if (!node.hasNonNull(field)) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "JWT inválido");
        }
        return node.get(field).asText();
    }

    private record LabPrincipal(String username, String role) {
    }
}
