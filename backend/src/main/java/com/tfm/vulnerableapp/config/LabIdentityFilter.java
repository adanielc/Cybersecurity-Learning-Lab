package com.tfm.vulnerableapp.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public class LabIdentityFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ID = "X-Lab-User-Id";
    public static final String HEADER_USERNAME = "X-Lab-Username";
    public static final String HEADER_ROLE = "X-Lab-Role";

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Optional<Long> userId = parseLongHeader(request.getHeader(HEADER_USER_ID));
            String username = request.getHeader(HEADER_USERNAME);
            String role = request.getHeader(HEADER_ROLE);

            if (userId.isPresent() && hasText(username) && hasText(role)) {
                var authentication = new UsernamePasswordAuthenticationToken(
                    new LabPrincipal(userId.get(), username.trim(), role.trim()),
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_" + role.trim().toUpperCase()))
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private Optional<Long> parseLongHeader(String value) {
        if (!hasText(value)) {
            return Optional.empty();
        }

        try {
            return Optional.of(Long.parseLong(value.trim()));
        } catch (NumberFormatException ex) {
            return Optional.empty();
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
