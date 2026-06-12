package com.tfm.vulnerableapp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "lab_exposure_users")
public class DataExposureUserEntity {

    @Id
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(name = "visible_name", nullable = false)
    private String visibleName;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "internal_notes", nullable = false, length = 1000)
    private String internalNotes;

    @Column(name = "role_internal", nullable = false)
    private String roleInternal;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_login_ip", nullable = false)
    private String lastLoginIp;

    protected DataExposureUserEntity() {
    }

    public DataExposureUserEntity(
        Long id,
        String username,
        String visibleName,
        String passwordHash,
        String internalNotes,
        String roleInternal,
        Instant createdAt,
        String lastLoginIp
    ) {
        this.id = id;
        this.username = username;
        this.visibleName = visibleName;
        this.passwordHash = passwordHash;
        this.internalNotes = internalNotes;
        this.roleInternal = roleInternal;
        this.createdAt = createdAt;
        this.lastLoginIp = lastLoginIp;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getVisibleName() {
        return visibleName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getInternalNotes() {
        return internalNotes;
    }

    public String getRoleInternal() {
        return roleInternal;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getLastLoginIp() {
        return lastLoginIp;
    }
}
