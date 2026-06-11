package com.tfm.vulnerableapp.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public record SecurityModeProperties(Mode mode, Cors cors, Jwt jwt) {

    public SecurityModeProperties {
        mode = mode == null ? Mode.INSECURE : mode;
        cors = cors == null ? new Cors(List.of("http://localhost:8081")) : cors;
        jwt = jwt == null ? new Jwt("dev-lab-secret-dev-lab-secret-dev-lab-secret") : jwt;
    }

    public enum Mode {
        INSECURE,
        SECURE
    }

    public record Cors(List<String> allowedOrigins) {
    }

    public record Jwt(String secret) {
    }
}
