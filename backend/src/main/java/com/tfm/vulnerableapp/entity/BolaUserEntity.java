package com.tfm.vulnerableapp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "lab_bola_users")
public class BolaUserEntity {

    @Id
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String role;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(nullable = false)
    private String department;

    protected BolaUserEntity() {
    }

    public BolaUserEntity(Long id, String username, String email, String role, String fullName, String department) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.fullName = fullName;
        this.department = department;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getRole() {
        return role;
    }

    public String getFullName() {
        return fullName;
    }

    public String getDepartment() {
        return department;
    }
}
