# Cybersecurity Learning Lab

Laboratorio educativo local para estudiar vulnerabilidades y remediaciones en una arquitectura moderna basada en SPA + API REST + Docker.

## Stack

- Backend: Java 17, Spring Boot 3, Spring Security, Spring Data JPA, PostgreSQL y MongoDB.
- Frontend: Vue 2 y Vuetify 2.
- Infraestructura: Docker y Docker Compose.
- Autenticacion: JWT.

## Estructura actual

```text
.
├── backend/
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/tfm/vulnerableapp/
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
│       ├── components/
│       ├── router/
│       ├── styles/
│       ├── utils/
│       └── views/
├── docker-compose.yml
├── docker-compose.insecure.yml
├── .env
├── docs/
│   └── docker-security.md
└── README.md
```

## Arranque local con Docker Compose

### Compose controlado

```bash
docker compose up --build
```

### Compose inseguro para el laboratorio de Docker

Docker Compose lee automaticamente `.env` desde la raiz del proyecto.

```bash
docker compose -f docker-compose.insecure.yml up --build
```

### URLs y puertos

- Frontend: http://localhost:8083
- Backend: http://localhost:8082
- API health: http://localhost:8082/api/health
- Spring Actuator health: http://localhost:8082/actuator/health
- Spring Actuator info: http://localhost:8082/actuator/info
- PostgreSQL: `localhost:5432`
- MongoDB: `localhost:27018`

### URLs del compose inseguro

- Frontend: http://localhost:8080
- Backend: http://localhost:8081
- PostgreSQL: `localhost:5432`
- MongoDB: `localhost:27017`

### Servicios del compose actual

| Servicio | Puerto contenedor | Puerto host | Observacion |
| --- | --- | --- | --- |
| frontend | 80 | 8083 | SPA servida por Nginx |
| backend | 8080 | 8082 | Spring Boot REST API |
| postgres | 5432 | 5432 | Persistencia relacional |
| mongo | 27017 | 27018 | Persistencia documental |

## Rutas del frontend

Las vistas principales de la SPA son estas:

- `/` - Dashboard
- `/lab/sqli` - SQL Injection
- `/lab/nosqli` - NoSQL Injection
- `/lab/bola` - BOLA / IDOR
- `/lab/jwt` - JWT / Validacion
- `/lab/cors` - CORS
- `/lab/exposure` - Excessive Data Exposure
- `/lab/docker-security` - Docker inseguro
- `/lab/rate-limit` - Rate Limiting
- `/lab/xss` - XSS
- `/lab/token-storage` - Almacenamiento de tokens
- `/lab/broken-auth` - Broken Authentication

Las rutas bajo `/labs/...` siguen funcionando como alias heredados para no romper enlaces anteriores.

## Uso de los laboratorios

Cada vista presenta una version vulnerable y una version segura del mismo caso de uso. El objetivo es comparar el error de concepcion y la remediacion tecnica:

- SQL Injection: concatenacion insegura vs consultas parametrizadas.
- NoSQL Injection: aceptar JSON arbitrario vs DTOs tipados.
- BOLA / IDOR: confiar en el ID de la URL vs validar ownership y rol.
- JWT: decodificar claims sin validar vs verificar firma, expiracion y proposito.
- CORS: politica amplia vs origenes y metodos restringidos.
- Excessive Data Exposure: devolver entidades completas vs DTOs publicos.
- Docker inseguro: puertos de datos publicados, contenedores root y ausencia de aislamiento.
- Rate Limiting: permitir intentos ilimitados vs responder con HTTP 429.
- XSS: renderizar HTML sin sanitizar vs escapar o neutralizar contenido.
- Almacenamiento de tokens: localStorage vs memoria o cookie HttpOnly.
- Broken Authentication: mensajes reveladores y contrasenas debiles vs errores genericos y BCrypt.

## Laboratorio de Docker inseguro

El archivo `docker-compose.insecure.yml` levanta una variante pensada para demostrar errores comunes de
despliegue:

- PostgreSQL y MongoDB quedan expuestos al host.
- El backend se ejecuta como `root`.
- No hay healthchecks.
- La red no está aislada como en un entorno endurecido.
- Las credenciales son de laboratorio y no deben usarse fuera de un entorno controlado.

### Cómo probar la exposición

Una vez levantado el compose inseguro, puedes comprobar que los servicios sensibles responden desde el host
sin pasar por la API:

```bash
psql -h localhost -p 5432 -U tfm_user -d tfm_lab
mongosh "mongodb://vulnlab:vulnlab@localhost:27017/tfm_lab?authSource=admin"
```

### Cómo evitarlo

- No publicar PostgreSQL ni MongoDB al host si no es imprescindible.
- Usar una red interna para backend y datos.
- Ejecutar contenedores de aplicación como usuario no root.
- Añadir healthchecks.
- Gestionar credenciales fuera del repositorio.

## Endpoints principales del backend

### Salud y observabilidad

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| GET | `/api/health` | Estado basico de la API. |
| GET | `/actuator/health` | Health check de Spring Boot Actuator. |
| GET | `/actuator/info` | Informacion basica del proceso y la aplicacion. |

### SQL Injection

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| GET | `/api/lab/sqli/users/search` | Busqueda vulnerable por `username`. |
| GET | `/api/lab/sqli/users/search-secure` | Busqueda segura parametrizada. |
| GET | `/api/lab/sqli/users/search-mode` | Punto unico que alterna segun la configuracion del laboratorio. |

### NoSQL Injection

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| POST | `/api/lab/nosqli/login` | Login documental vulnerable. |
| POST | `/api/lab/nosqli/login-secure` | Login documental seguro con DTOs tipados. |
| POST | `/api/lab/nosqli/search-comments` | Busqueda vulnerable de comentarios. |
| POST | `/api/lab/nosqli/search-comments-secure` | Busqueda segura de comentarios. |

### BOLA / IDOR

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| GET | `/api/lab/bola/profile/{userId}` | Perfil vulnerable por identificador. |
| GET | `/api/lab/bola/profile-secure/{userId}` | Perfil seguro con control de ownership y rol. |
| GET | `/api/lab/bola/my-profile` | Perfil del usuario autenticado. |

### JWT y almacenamiento de tokens

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| POST | `/api/lab/token-storage/login` | Emite un JWT de laboratorio. |
| GET | `/api/lab/token-storage/me` | Valida y devuelve el usuario autenticado. |

> La vista `/lab/jwt` se centra en la validacion del token y usa los mismos endpoints de emision y verificacion.

### CORS

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| GET | `/api/lab/cors/public-data` | Dato publico de ejemplo. |
| GET | `/api/lab/cors/private-data` | Dato privado expuesto bajo politica permisiva. |
| GET | `/api/lab/cors/secure-private-data` | Dato privado bajo politica restringida. |

### Excessive Data Exposure

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| GET | `/api/lab/exposure/users/{id}` | Devuelve la entidad completa de usuario. |
| GET | `/api/lab/exposure/users-secure/{id}` | Devuelve un DTO publico reducido. |
| GET | `/api/lab/exposure/users` | Listado completo vulnerable. |

### Rate Limiting

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| POST | `/api/lab/rate-limit/login-insecure` | Login sin limite de intentos. |
| POST | `/api/lab/rate-limit/login-secure` | Login con limite temporal y HTTP 429. |
| GET | `/api/lab/rate-limit/status` | Estado del contador y la ventana activa. |

### XSS

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| POST | `/api/lab/xss/comments` | Guarda comentarios sin sanitizar. |
| GET | `/api/lab/xss/comments` | Lee comentarios vulnerables. |
| POST | `/api/lab/xss/comments-secure` | Guarda comentarios neutralizados. |
| GET | `/api/lab/xss/comments-secure` | Lee comentarios neutralizados. |

### Broken Authentication

| Metodo | Ruta | Descripcion |
| --- | --- | --- |
| POST | `/api/lab/auth/login-insecure` | Login vulnerable con mensajes reveladores. |
| POST | `/api/lab/auth/login-secure` | Login seguro con mensajes genericos. |
| POST | `/api/lab/auth/register-insecure` | Registro vulnerable con contrasenas debiles. |
| POST | `/api/lab/auth/register-secure` | Registro seguro con politica de contrasena. |

## Configuracion y entorno

Variables principales de entorno:

- `APP_SECURITY_MODE`
- `APP_CORS_ALLOWED_ORIGINS`
- `JWT_SECRET`
- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `SPRING_DATA_MONGODB_URI`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `MONGO_INITDB_ROOT_USERNAME`
- `MONGO_INITDB_ROOT_PASSWORD`
- `MONGO_DATABASE`

## Notas de seguridad

- El proyecto esta pensado para laboratorio local, controlado y academico.
- No debe desplegarse en produccion tal y como esta.
- Contiene vulnerabilidades intencionales para docencia.
- No deben usarse credenciales reales.
