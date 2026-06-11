# TFM Vulnerable Architecture Lab

Laboratorio educativo local para comparar vulnerabilidades y remediaciones en una arquitectura moderna basada en SPA + API REST + Docker.

## Stack

- Backend: Java 17, Spring Boot 3, Spring Security, Spring Data JPA, PostgreSQL y MongoDB.
- Frontend: Vue 2 y Vuetify 2.
- Infraestructura: Docker y Docker Compose.
- Autenticacion: JWT.

## Estructura inicial

```text
.
├── backend/
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/tfm/vulnerableapp/
│       │   ├── VulnerableAppApplication.java
│       │   ├── config/
│       │   ├── controller/
│       │   ├── dto/
│       │   ├── entity/
│       │   ├── repository/
│       │   └── service/
│       └── resources/application.yml
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
├── docker-compose.yml
├── .env.example
└── README.md
```

## Arranque local con Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

URLs locales:

- Frontend: http://localhost:8083
- Backend health: http://localhost:8082/api/health
- Spring actuator health: http://localhost:8082/actuator/health
- PostgreSQL: `localhost:5433`
- MongoDB: `localhost:27017`

## Variantes Docker

### Modo vulnerable

```bash
docker compose -f docker-compose.insecure.yml up --build
```

### Modo seguro

```bash
docker compose -f docker-compose.secure.yml up --build
```

### Despliegue controlado por defecto

```bash
docker compose up --build
```

Este `compose` principal mantiene la experiencia de desarrollo local, pero no debe tomarse como configuración de producción.

## Arranque desde IntelliJ IDEA

1. Abre la carpeta del proyecto como monorepo.
2. Importa `backend/pom.xml` como proyecto Maven.
3. Levanta PostgreSQL y MongoDB con `docker compose up postgres mongo`.
4. Ejecuta `VulnerableAppApplication` con Java 17.
5. Para el frontend, abre una terminal en `frontend/` y ejecuta:

```bash
npm install
npm run serve -- --host 0.0.0.0
```

## Endpoints iniciales

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| GET | `/api/health` | Estado basico de la API. |
| POST | `/api/lab/token-storage/login` | Emite un JWT de laboratorio con datos educativos del usuario. |
| GET | `/api/lab/token-storage/me` | Devuelve el usuario autenticado a partir de `Authorization` o cookie HttpOnly. |
| POST | `/api/lab/auth/login-insecure` | Login vulnerable con mensajes diferenciados para enumeración. |
| POST | `/api/lab/auth/login-secure` | Login endurecido con mensajes genéricos y rate limiting. |
| POST | `/api/lab/auth/register-insecure` | Registro vulnerable con contraseñas débiles y errores reveladores. |
| POST | `/api/lab/auth/register-secure` | Registro seguro con política de contraseña y BCrypt. |
| GET | `/actuator/health` | Health check de Spring Boot Actuator. |

## Plan de fases

1. Base tecnica: monorepo, Docker Compose, Spring Boot, Vue 2/Vuetify 2, PostgreSQL y MongoDB.
2. Dominio y autenticacion: registro, login JWT, roles USER/ADMIN, perfil y listado de usuarios.
3. Separacion clara entre servicios vulnerables y seguros.
4. Laboratorios vulnerables: SQL Injection, NoSQL Injection, BOLA/IDOR, JWT inseguro, CORS laxo, excessive data exposure, ausencia de rate limiting, XSS, token storage inseguro y configuraciones Docker inseguras.
5. Remediaciones: queries parametrizadas, autorizacion por ownership, hardening de JWT/CORS/Docker, sanitizacion, DTOs seguros y rate limiting.
6. Documentacion didactica: endpoints, escenarios locales y matriz vulnerabilidad/remediacion.

## Rutas del frontend

Los laboratorios quedan agrupados bajo estas rutas de Vue:

- `/lab/sqli`
- `/lab/nosqli`
- `/lab/bola`
- `/lab/jwt`
- `/lab/cors`
- `/lab/exposure`
- `/lab/rate-limit`
- `/lab/xss`
- `/lab/token-storage`
- `/lab/broken-auth`

Las rutas antiguas bajo `/labs/...` siguen funcionando como alias para no romper enlaces previos.

## Almacenamiento inseguro de tokens JWT en frontend

Este laboratorio compara dos patrones de almacenamiento de un JWT emitido por el backend:

- Modo vulnerable: guardar el token en `localStorage`.
- Modo seguro: mantener el token en memoria mientras la pestaña siga abierta.
- Variante opcional: usar una cookie `HttpOnly` emitida por el backend, con `SameSite` y `Secure` cuando el despliegue lo permita.

La idea no es decir que `localStorage` sea malo por definición, sino mostrar que su uso aumenta el impacto de una XSS. Si un atacante consigue ejecutar JavaScript en la página, podrá leer el token y reutilizarlo.

### Riesgos a explicar en clase

- Cualquier JavaScript de la misma página puede leer `localStorage`.
- El frontend no debe ser la única barrera de seguridad.
- `HttpOnly` impide que JavaScript lea la cookie, pero sigue requiriendo protección frente a CSRF y una política CORS correcta.
- Mantener el token en memoria reduce la persistencia de la exposición, aunque no elimina por sí solo el riesgo de XSS.

### Alternativas más seguras

- Cookie `HttpOnly` + `SameSite` + `Secure`.
- Token en memoria.
- Refresh token controlado y acceso corto.
- CSP y mitigación real de XSS.

## Broken Authentication

Este laboratorio muestra patrones comunes de autenticacion rota:

- Enumeracion de usuarios por mensajes distintos.
- Contraseñas debiles aceptadas en la ruta vulnerable.
- Hashing inseguro o inexistente en la parte vulnerable.
- Mensajes genericos y politica minima de contrasena en la ruta segura.
- Rate limiting para frenar fuerza bruta en login seguro.

### Ejemplos de uso

- Login vulnerable: `POST /api/lab/auth/login-insecure`
- Login seguro: `POST /api/lab/auth/login-secure`
- Registro vulnerable: `POST /api/lab/auth/register-insecure`
- Registro seguro: `POST /api/lab/auth/register-secure`

### Idea didactica

Cuando el backend responde con "usuario no encontrado" o "contrasena incorrecta", un atacante puede probar nombres de cuenta y confirmar cuales existen. En la ruta segura, el error es generico y el backend no revela si el usuario existe ni si fallo la contrasena. La combinacion de BCrypt, politica de contrasenas y rate limiting reduce mucho el impacto de fuerza bruta y reutilizacion de credenciales.

## Nota de alcance

Este proyecto esta pensado exclusivamente para un entorno local, controlado y academico. Las vulnerabilidades futuras deben quedar confinadas al laboratorio y no deben incluir malware, persistencia maliciosa, acciones destructivas ni explotacion de sistemas externos.

## Comparativa Docker

| Aspecto | Configuracion vulnerable | Configuracion segura | Riesgo mitigado |
| --- | --- | --- | --- |
| Puertos de bases de datos | PostgreSQL y MongoDB expuestos al host | No se publican al host | Reduce superficie de ataque |
| Credenciales | Simples y predecibles | Variables de entorno de ejemplo no productivas | Evita credenciales triviales |
| Usuario de contenedor | `root` | Usuario no root | Limita impacto de una rotura de contenedor |
| Red | Red por defecto sin aislamiento | Red interna para backend y datos | Aísla servicios sensibles |
| Healthchecks | No se usan | Activados en backend y bases de datos | Mejora arranque y observabilidad |
| Secretos | No se usan | Variables separadas en `.env.example` | Evita incrustar secretos reales |

## Despliegue mediante Docker Hub

### Publicar imágenes

1. Inicia sesión en Docker Hub.

```bash
docker login
```

2. Construye y publica las imágenes.

```bash
./scripts/docker-build-push.sh scoresby
```

Las imágenes esperadas son:

- `scoresby/tfm-cybersecurity-lab-backend:latest`
- `scoresby/tfm-cybersecurity-lab-frontend:latest`

### Descargar y ejecutar en otro equipo

```bash
git clone https://github.com/adanielc/uclm-vulnerable.git
cd tfm-cybersecurity-lab
cp .env.example .env
docker compose -f docker-compose.hub.yml pull
docker compose -f docker-compose.hub.yml up -d
```

O, si prefieres un atajo:

```bash
./scripts/docker-run-from-hub.sh
```

### Acceso a la aplicación

- Frontend: http://localhost:8080
- Backend: http://localhost:8081
- PostgreSQL: interno en Docker
- MongoDB: interno en Docker

### Parar el laboratorio

```bash
docker compose -f docker-compose.hub.yml down
```

### Borrar volúmenes

```bash
docker compose -f docker-compose.hub.yml down -v
```

### Notas de seguridad

- Las imágenes están pensadas para laboratorio local.
- No deben desplegarse en producción.
- La aplicación contiene vulnerabilidades intencionales.
- No se deben usar credenciales reales.
- El modo de laboratorio solo debe activarse en un entorno controlado.
- Para pruebas seguras puede usarse la variante protegida del laboratorio.
