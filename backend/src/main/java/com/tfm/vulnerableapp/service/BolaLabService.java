package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.config.LabPrincipal;
import com.tfm.vulnerableapp.dto.UserProfileDto;
import com.tfm.vulnerableapp.entity.BolaUserEntity;
import com.tfm.vulnerableapp.repository.BolaUserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

@Service
public class BolaLabService {

    private final BolaUserRepository bolaUserRepository;

    public BolaLabService(BolaUserRepository bolaUserRepository) {
        this.bolaUserRepository = bolaUserRepository;
    }

    @PostConstruct
    public void seedData() {
        seed(1L, "admin", "admin@vulnerable-lab.local", "ADMIN", "System Administrator", "Security");
        seed(2L, "alice", "alice@vulnerable-lab.local", "USER", "Alice Carter", "Engineering");
        seed(3L, "bob", "bob@vulnerable-lab.local", "USER", "Bob Stone", "Support");
        seed(4L, "auditor", "auditor@vulnerable-lab.local", "ADMIN", "Audit User", "Compliance");
    }

    public UserProfileDto getProfileVulnerable(Long userId) {
        /*
         * VULNERABLE: se confia en el ID de la URL y se devuelve el perfil sin
         * comprobar si pertenece al usuario autenticado.
         */
        return findProfileOrThrow(userId);
    }

    public UserProfileDto getProfileSecure(Long userId) {
        LabPrincipal principal = requireAuthenticatedPrincipal();
        boolean isAdmin = hasRole("ADMIN");
        boolean isOwner = Objects.equals(principal.userId(), userId);

        /*
         * SECURE: la autorizacion se hace en el backend, comparando el recurso
         * solicitado con la identidad autenticada. Solo el propio usuario o un
         * admin pueden acceder.
         */
        if (!isOwner && !isAdmin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "No tienes permisos para ver este perfil");
        }

        return findProfileOrThrow(userId);
    }

    public UserProfileDto getCurrentUserProfileSecure() {
        LabPrincipal principal = requireAuthenticatedPrincipal();
        return getProfileSecure(principal.userId());
    }

    private UserProfileDto findProfileOrThrow(Long userId) {
        BolaUserEntity entity = bolaUserRepository.findById(userId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado"));

        return new UserProfileDto(
            entity.getId(),
            entity.getUsername(),
            entity.getEmail(),
            entity.getRole(),
            entity.getFullName(),
            entity.getDepartment()
        );
    }

    private LabPrincipal requireAuthenticatedPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No hay un usuario autenticado");
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof LabPrincipal labPrincipal) {
            return labPrincipal;
        }

        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "La autenticacion no contiene un principal de laboratorio valido");
    }

    private boolean hasRole(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }

        String expected = "ROLE_" + role.toUpperCase();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (expected.equals(authority.getAuthority())) {
                return true;
            }
        }

        return false;
    }

    private void seed(Long id, String username, String email, String role, String fullName, String department) {
        if (bolaUserRepository.existsById(id)) {
            return;
        }

        bolaUserRepository.save(new BolaUserEntity(id, username, email, role, fullName, department));
    }
}
