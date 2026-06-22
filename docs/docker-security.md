# Docker Security Guide

Este documento resume la configuracion Docker actual del laboratorio y las
recomendaciones de endurecimiento que deben revisarse antes de pensar en un
despliegue fuera del entorno academico.

## Compose actual del proyecto

El fichero activo es `docker-compose.yml` y levanta:

- `frontend` en `http://localhost:8083`
- `backend` en `http://localhost:8082`
- `postgres` solo en la red interna Docker
- `mongo` solo en la red interna Docker

Los servicios de datos usan volumenes persistentes y healthchecks. El backend
se ejecuta como usuario no root en la configuracion actual.

## Variante insegura para el laboratorio

El fichero `docker-compose.insecure.yml` publica los servicios sensibles al
host y quita varias medidas de endurecimiento para que el alumno pueda
observar el problema de forma directa:

- PostgreSQL publicado en `localhost:5432`.
- MongoDB publicado en `localhost:27018`.
- Backend publicado en `localhost:8082` y ejecutado como `root`.
- Frontend publicado en `localhost:8083`.
- Sin healthchecks.
- Sin aislamiento de red adicional.

Arranque:

Docker Compose lee automaticamente `.env` desde la raiz del proyecto.

```bash
docker compose -f docker-compose.insecure.yml up --build
```

## Principios de seguridad aplicados

- Separacion de frontend, backend y bases de datos en servicios distintos.
- PostgreSQL y MongoDB sin publicacion al host en el compose controlado.
- Uso de variables de entorno para configuracion sensible.
- Healthchecks para coordinar el arranque.
- Ejecutar la aplicacion como usuario no root cuando es viable.
- Mantener la superficie publica limitada a lo necesario para el laboratorio.

## Puntos a revisar antes de produccion

- No publicar PostgreSQL ni MongoDB al host salvo necesidad real.
- Usar secretos gestionados externamente en lugar de credenciales de ejemplo.
- Revisar `JWT_SECRET` y las politicas CORS.
- Verificar que la imagen de backend y frontend se construye con versiones
  actualizadas y base minima.
- Mantener logs, backups y observabilidad separados de la configuracion de
  desarrollo.
- Mantener los servicios sensibles en una red interna cuando el caso de uso lo
  permita.

## Observacion academica

Este laboratorio esta disenado para un entorno local y controlado. Las
configuraciones actuales no deben tomarse como plantilla de produccion sin una
revision completa de seguridad.
