package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.dto.LoginRequest;
import com.tfm.vulnerableapp.dto.SqlInjectionLoginResponse;
import com.tfm.vulnerableapp.dto.SqlInjectionUserResponse;
import jakarta.annotation.PostConstruct;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

@Service
public class SqlInjectionLabService {

    private static final RowMapper<SqlInjectionUserResponse> USER_ROW_MAPPER = (rs, rowNum) -> new SqlInjectionUserResponse(
            rs.getLong("id"),
            rs.getString("username"),
            rs.getString("email"),
            rs.getString("role")
    );

    private final JdbcTemplate jdbcTemplate;

    public SqlInjectionLabService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostConstruct
    public void init() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS lab_users (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(80) NOT NULL UNIQUE,
                    email VARCHAR(180) NOT NULL,
                    role VARCHAR(40) NOT NULL,
                    password VARCHAR(120)
                )
                """);
        jdbcTemplate.execute("ALTER TABLE lab_users ADD COLUMN IF NOT EXISTS password VARCHAR(120)");

        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM lab_users", Integer.class);
        if (count == null || count == 0) {
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role, password) VALUES (?, ?, ?, ?)", "admin", "admin@lab.local", "ADMIN", "admin123");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role, password) VALUES (?, ?, ?, ?)", "alice", "alice@lab.local", "USER", "password123");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role, password) VALUES (?, ?, ?, ?)", "bob", "bob@lab.local", "USER", "password123");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role, password) VALUES (?, ?, ?, ?)", "auditor", "auditor@lab.local", "ADMIN", "audit123");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role, password) VALUES (?, ?, ?, ?)", "charlie", "charlie@lab.local", "USER", "charlie123");
        }

        seedPasswordIfMissing("admin", "admin123");
        seedPasswordIfMissing("alice", "password123");
        seedPasswordIfMissing("bob", "password123");
        seedPasswordIfMissing("auditor", "audit123");
        seedPasswordIfMissing("charlie", "charlie123");
    }

    public List<SqlInjectionUserResponse> searchVulnerable(String username) {
        String sql = "SELECT id, username, email, role FROM lab_users WHERE username = '" + username + "'";
        return jdbcTemplate.query(sql, USER_ROW_MAPPER);
    }

    public List<SqlInjectionUserResponse> searchSecure(String username) {
        String sql = "SELECT id, username, email, role FROM lab_users WHERE username = ?";
        return jdbcTemplate.query(sql, USER_ROW_MAPPER, username);
    }

    public SqlInjectionLoginResponse loginVulnerable(LoginRequest request) {
        String sql = "SELECT id, username, email, role FROM lab_users WHERE username = '" + request.username()
                + "' AND password = '" + request.password() + "'";
        List<SqlInjectionUserResponse> users = jdbcTemplate.query(sql, USER_ROW_MAPPER);
        return new SqlInjectionLoginResponse(!users.isEmpty(), users.size(), users);
    }

    public SqlInjectionLoginResponse loginSecure(LoginRequest request) {
        String sql = "SELECT id, username, email, role FROM lab_users WHERE username = ? AND password = ?";
        List<SqlInjectionUserResponse> users = jdbcTemplate.query(sql, USER_ROW_MAPPER, request.username(), request.password());
        return new SqlInjectionLoginResponse(!users.isEmpty(), users.size(), users);
    }

    private void seedPasswordIfMissing(String username, String password) {
        jdbcTemplate.update(
                "UPDATE lab_users SET password = ? WHERE username = ? AND (password IS NULL OR password = '')",
                password,
                username
        );
    }
}
