export const DEFAULT_API_BASE_URL = process.env.VUE_APP_API_BASE_URL || 'http://localhost:8082/api'

export function prettyJson (value) {
  if (value === null || value === undefined || value === '') {
    return '-'
  }

  if (typeof value === 'string') {
    return value
  }

  try {
    return JSON.stringify(value, null, 2)
  } catch (error) {
    return String(value)
  }
}

export function apiMessage (error) {
  if (!error || !error.response) {
    return 'No se pudo conectar con la API.'
  }

  const body = error.response.data
  if (body && typeof body === 'object') {
    if (body.message) {
      return body.message
    }

    return `HTTP ${error.response.status}`
  }

  return typeof body === 'string' && body.trim() ? body : `HTTP ${error.response.status}`
}

export function apiPayload (error) {
  return error && error.response ? error.response.data : null
}
