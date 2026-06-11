#!/usr/bin/env bash

set -euo pipefail

if ! docker info >/dev/null 2>&1; then
  echo "Docker no esta disponible. Inicia Docker Desktop o el daemon y vuelve a intentarlo."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Descargando imágenes desde Docker Hub..."
docker compose -f "${ROOT_DIR}/docker-compose.hub.yml" pull

echo "Levantando el laboratorio desde Docker Hub..."
docker compose -f "${ROOT_DIR}/docker-compose.hub.yml" up -d

echo "Laboratorio disponible en http://localhost:8080"
