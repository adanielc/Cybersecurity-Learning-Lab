package com.tfm.vulnerableapp.controller;

import com.tfm.vulnerableapp.dto.CorsLabResponseDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
@RequestMapping("/api/lab/cors")
public class CorsLabController {


    public static final String INSECURE = "INSECURE";
    public static final String SECURE = "SECURE";

    @GetMapping("/public-data")
    public ResponseEntity<CorsLabResponseDto> publicData() {
        return ResponseEntity.ok(buildResponse(
            "/api/lab/cors/public-data",
            "Datos públicos del laboratorio accesibles desde cualquier origen permitido por la política CORS.",
            "No contiene información sensible.",
                INSECURE
        ));
    }

    @GetMapping("/private-data")
    public ResponseEntity<CorsLabResponseDto> privateData() {
        return ResponseEntity.ok(buildResponse(
            "/api/lab/cors/private-data",
            "Dato privado educativo. Si la política CORS es demasiado amplia, un sitio ajeno podría leer esta respuesta desde el navegador.",
            "Resumen interno del laboratorio: no exponer a orígenes no confiables.",
                INSECURE
        ));
    }

    @GetMapping("/secure-private-data")
    public ResponseEntity<CorsLabResponseDto> securePrivateData() {
        return ResponseEntity.ok(buildResponse(
            "/api/lab/cors/secure-private-data",
            "Mismo dato privado, pero pensado para ser leído solo desde el origen legítimo del frontend bajo una política CORS restrictiva.",
            "Resumen interno del laboratorio: acceso pensado solo para el frontend autorizado.",
                SECURE
        ));
    }

    private CorsLabResponseDto buildResponse(String endpoint, String message, String sampleData, String mode) {
        String policy = Objects.equals(mode, INSECURE)
            ? "INSECURE: allowedOriginPatterns(*), methods amplios, headers amplios"
            : "SECURE: allowedOrigins restringidos, metodos GET/OPTIONS, headers limitados";

        String title = Objects.equals(mode, INSECURE) ? "Política permisiva" : "Política restringida";

        return new CorsLabResponseDto(
            endpoint,
            mode,
            policy,
            title,
            message,
            sampleData
        );
    }
}
