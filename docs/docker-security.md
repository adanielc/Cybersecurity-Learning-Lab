# Docker Security Lab

Este documento compara la configuración Docker del laboratorio en tres niveles:

- `docker-compose.yml`: desarrollo controlado.
- `docker-compose.insecure.yml`: variante vulnerable para demostrar malas prácticas.
- `docker-compose.secure.yml`: variante endurecida de referencia.

## Principios usados

- No publicar bases de datos al host salvo necesidad explícita.
- Usar redes internas para aislar backend y datos.
- Ejecutar los contenedores de aplicación como usuario no root.
- Añadir healthchecks para coordinar el arranque.
- Evitar credenciales reales y secretos productivos.
- Mantener los valores sensibles en `.env` o variables de entorno.

## Qué hace insegura la variante vulnerable

- Expone PostgreSQL y MongoDB al host.
- Usa credenciales triviales y predecibles.
- Ejecuta backend y frontend como `root`.
- No usa healthchecks.
- No separa la red interna de datos.
- No usa secretos ni perfiles.

## Qué mejora la variante segura

- PostgreSQL y MongoDB no se publican al host.
- Backend y bases de datos comparten una red interna aislada.
- Backend y frontend se ejecutan como usuarios no root.
- Hay healthchecks para PostgreSQL y MongoDB.
- Las credenciales de ejemplo no son productivas.
- El `APP_SECURITY_MODE` queda en `SECURE`.

## Qué cambiar antes de producción

- Sustituir cualquier credencial de ejemplo por secretos gestionados externamente.
- Eliminar puertos publicados que no sean estrictamente necesarios.
- Usar `APP_JWT_SECRET` fuerte y rotado.
- Considerar un orquestador o gestor de secretos real.
- Revisar `APP_CORS_ALLOWED_ORIGINS` para que no admita orígenes innecesarios.
- Asegurar que la imagen se actualiza con frecuencia y que el usuario no root está validado en CI.

