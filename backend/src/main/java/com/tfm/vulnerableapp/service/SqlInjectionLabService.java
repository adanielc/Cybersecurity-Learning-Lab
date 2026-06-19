package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.dto.SqlInjectionUserResponse;
import jakarta.annotation.PostConstruct;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SqlInjectionLabService {

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
                    role VARCHAR(40) NOT NULL
                )
                """);

        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM lab_users", Integer.class);
        if (count == null || count == 0) {
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role) VALUES (?, ?, ?)", "admin", "admin@lab.local", "ADMIN");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role) VALUES (?, ?, ?)", "alice", "alice@lab.local", "USER");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role) VALUES (?, ?, ?)", "bob", "bob@lab.local", "USER");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role) VALUES (?, ?, ?)", "auditor", "auditor@lab.local", "ADMIN");
            jdbcTemplate.update("INSERT INTO lab_users (username, email, role) VALUES (?, ?, ?)", "charlie", "charlie@lab.local", "USER");
        }
    }

    public List<SqlInjectionUserResponse> searchVulnerable(String username) {
        String sql = "SELECT id, username, email, role FROM lab_users WHERE username = '" + username + "'";
        return jdbcTemplate.query(sql, (rs, rowNum) -> new SqlInjectionUserResponse(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("role")
        ));
    }

    public List<SqlInjectionUserResponse> searchSecure(String username) {
        String sql = "SELECT id, username, email, role FROM lab_users WHERE username = ?";
        return jdbcTemplate.query(sql, (rs, rowNum) -> new SqlInjectionUserResponse(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("role")
        ), username);
    }
}
