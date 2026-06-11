package com.tfm.vulnerableapp;

import com.tfm.vulnerableapp.config.SecurityModeProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(SecurityModeProperties.class)
public class VulnerableAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableAppApplication.class, args);
    }
}
