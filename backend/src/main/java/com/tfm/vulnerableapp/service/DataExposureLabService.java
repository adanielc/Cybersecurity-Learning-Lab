package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.config.SecurityModeProperties;
import com.tfm.vulnerableapp.dto.PublicUserDto;
import com.tfm.vulnerableapp.entity.DataExposureUserEntity;
import com.tfm.vulnerableapp.repository.DataExposureUserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;

@Service
public class DataExposureLabService {

    private final DataExposureUserRepository dataExposureUserRepository;
    private final SecurityModeProperties securityModeProperties;

    public DataExposureLabService(
        DataExposureUserRepository dataExposureUserRepository,
        SecurityModeProperties securityModeProperties
    ) {
        this.dataExposureUserRepository = dataExposureUserRepository;
        this.securityModeProperties = securityModeProperties;
    }

    @PostConstruct
    public void seedData() {
        seed(
            1L,
            "admin",
            "Administrator",
            "$2a$10$u1b3X4fQxV6q1uK9GmQm9e8zZs0mB9d0xV2n5mS6X3P3p1hQn1vOe",
            "Owner of the platform. Full access to sensitive operational data.",
            "PLATFORM_ADMIN",
            Instant.parse("2026-01-10T08:15:30Z"),
            "192.168.1.10"
        );
        seed(
            2L,
            "alice",
            "Alice Carter",
            "$2a$10$yN8bG8JfF2Q6W1cB9m3m4eXb1w8n6f4Jg9p4f7W0H1q8w2k6v8xPe",
            "Onboarding user. Internal note: requires extra review before export access.",
            "STANDARD_USER",
            Instant.parse("2026-02-03T12:00:00Z"),
            "10.10.10.21"
        );
        seed(
            3L,
            "bob",
            "Bob Stone",
            "$2a$10$kT4mC1vL5nQ7rS8aD2fH6jG9pM1sX4zV5bN7cQ8wE2rT6yU3iO0pQ",
            "Support agent. Internal note: should never see raw hashes outside the backend.",
            "SUPPORT",
            Instant.parse("2026-03-15T09:45:00Z"),
            "172.16.20.45"
        );
        seed(
            4L,
            "auditor",
            "Audit User",
            "$2a$10$zQ7wE2rT6yU3iO0pQ4mC1vL5nQ7rS8aD2fH6jG9pM1sX4zV5bN7c",
            "Read-only auditor. Internal note: monitor unusual login IPs.",
            "AUDITOR",
            Instant.parse("2026-04-21T18:20:10Z"),
            "203.0.113.77"
        );
    }

    /*
     * VULNERABLE: devolver la entidad JPA completa deja que Jackson serialice
     * todos los campos persistidos, incluidos passwordHash, notas internas,
     * roles internos y metadatos operativos. El backend nunca debe confiar en
     * que el frontend oculte esos campos despues.
     */
    public DataExposureUserEntity getUserVulnerable(Long id) {
        return dataExposureUserRepository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    /*
     * SECURE: se devuelve un DTO publico con solo los campos que el cliente
     * necesita ver. La serializacion queda controlada y no expone detalles
     * internos ni credenciales derivadas.
     */
    public PublicUserDto getUserSecure(Long id) {
        DataExposureUserEntity entity = getUserEntityOrThrow(id);
        return new PublicUserDto(entity.getId(), entity.getUsername(), entity.getVisibleName());
    }

    public List<?> listUsers() {
            return dataExposureUserRepository.findAll();
    }

    private DataExposureUserEntity getUserEntityOrThrow(Long id) {
        return dataExposureUserRepository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    private void seed(
        Long id,
        String username,
        String visibleName,
        String passwordHash,
        String internalNotes,
        String roleInternal,
        Instant createdAt,
        String lastLoginIp
    ) {
        if (dataExposureUserRepository.existsById(id)) {
            return;
        }

        dataExposureUserRepository.save(new DataExposureUserEntity(
            id,
            username,
            visibleName,
            passwordHash,
            internalNotes,
            roleInternal,
            createdAt,
            lastLoginIp
        ));
    }
}
