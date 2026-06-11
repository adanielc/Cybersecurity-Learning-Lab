#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "Uso: $0 <docker-hub-user>"
  echo "Ejemplo: $0 scoresby"
  exit 1
fi

DOCKER_HUB_USER="$1"
BACKEND_IMAGE="${DOCKER_HUB_USER}/tfm-cybersecurity-lab-backend:latest"
FRONTEND_IMAGE="${DOCKER_HUB_USER}/tfm-cybersecurity-lab-frontend:latest"
FRONTEND_API_BASE_URL="${VUE_APP_API_BASE_URL:-http://localhost:8081/api}"

if ! docker info >/dev/null 2>&1; then
  echo "Docker no esta disponible. Inicia Docker Desktop o el daemon y vuelve a intentarlo."
  exit 1
fi

echo "Construyendo imagen backend: ${BACKEND_IMAGE}"
docker build -t "${BACKEND_IMAGE}" ./backend

echo "Construyendo imagen frontend: ${FRONTEND_IMAGE}"
docker build \
  --build-arg "VUE_APP_API_BASE_URL=${FRONTEND_API_BASE_URL}" \
  -t "${FRONTEND_IMAGE}" \
  ./frontend

echo "Subiendo imagen backend a Docker Hub"
docker push "${BACKEND_IMAGE}"

echo "Subiendo imagen frontend a Docker Hub"
docker push "${FRONTEND_IMAGE}"

echo "Imágenes publicadas correctamente."
