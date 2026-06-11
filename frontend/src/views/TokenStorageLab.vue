<template>
  <v-container fluid class="lab-page">
    <v-row>
      <v-col cols="12" lg="8">
        <v-card outlined>
          <v-card-title class="lab-title">
            <v-icon left color="primary">
              mdi-shield-key
            </v-icon>
            Almacenamiento de tokens JWT
          </v-card-title>

          <v-divider />

          <v-card-text>
            <v-alert type="info" outlined dense>
              Este laboratorio compara guardar un JWT en <strong>localStorage</strong> frente a mantenerlo en
              <strong>memoria</strong> o, de forma opcional, emitirlo en una <strong>cookie HttpOnly</strong>.
            </v-alert>

            <v-row>
              <v-col cols="12" md="6">
                <v-text-field
                  v-model="form.username"
                  label="Username"
                  outlined
                  dense
                  hide-details="auto"
                />
              </v-col>
              <v-col cols="12" md="6">
                <v-text-field
                  v-model="form.password"
                  label="Password"
                  type="password"
                  outlined
                  dense
                  hide-details="auto"
                />
              </v-col>
            </v-row>

            <v-switch
              v-model="useHttpOnlyCookie"
              inset
              color="primary"
              label="Usar cookie HttpOnly opcional en el login seguro"
              class="mt-0"
            />

            <v-row class="mb-2">
              <v-col cols="12" md="6">
                <v-btn block color="warning" :loading="loadingVulnerable" @click="loginVulnerable">
                  Login modo vulnerable
                </v-btn>
              </v-col>
              <v-col cols="12" md="6">
                <v-btn block color="success" :loading="loadingSecure" @click="loginSecure">
                  Login modo seguro
                </v-btn>
              </v-col>
            </v-row>

            <v-row class="mb-4">
              <v-col cols="12" md="6">
                <v-btn block outlined color="primary" @click="readLocalStorageToken">
                  Leer token desde localStorage
                </v-btn>
              </v-col>
              <v-col cols="12" md="6">
                <v-btn block outlined color="secondary" :loading="loadingMe" @click="loadCurrentUser">
                  Consultar usuario actual
                </v-btn>
              </v-col>
            </v-row>

            <v-row class="mb-4">
              <v-col cols="12">
                <v-btn block outlined color="error" @click="logout">
                  Cerrar sesión
                </v-btn>
              </v-col>
            </v-row>

            <v-alert v-if="message" dense outlined type="success">
              {{ message }}
            </v-alert>
            <v-alert v-if="error" dense outlined type="error">
              {{ error }}
            </v-alert>

            <v-simple-table class="mt-4">
              <tbody>
                <tr>
                  <th>Origen actual</th>
                  <td>{{ browserOrigin }}</td>
                </tr>
                <tr>
                  <th>Token en memoria</th>
                  <td>{{ maskedToken(memoryToken) }}</td>
                </tr>
                <tr>
                  <th>Token en localStorage</th>
                  <td>{{ maskedToken(localStorageToken) }}</td>
                </tr>
                <tr>
                  <th>Token leído</th>
                  <td>{{ maskedToken(readTokenPreview) }}</td>
                </tr>
              </tbody>
            </v-simple-table>

            <v-card class="mt-6" outlined>
              <v-card-title class="subtitle-1">
                Respuesta de /me
              </v-card-title>
              <v-divider />
              <v-card-text>
                <v-simple-table v-if="meResponse">
                  <tbody>
                    <tr>
                      <th>Usuario</th>
                      <td>{{ meResponse.user.username }}</td>
                    </tr>
                    <tr>
                      <th>Nombre</th>
                      <td>{{ meResponse.user.displayName }}</td>
                    </tr>
                    <tr>
                      <th>Rol</th>
                      <td>{{ meResponse.user.role }}</td>
                    </tr>
                    <tr>
                      <th>Fuente del token</th>
                      <td>{{ meResponse.tokenSource }}</td>
                    </tr>
                    <tr>
                      <th>Propósito</th>
                      <td>{{ meResponse.tokenPurpose }}</td>
                    </tr>
                  </tbody>
                </v-simple-table>
                <v-alert v-else type="info" outlined dense>
                  Aún no se ha consultado el endpoint /me.
                </v-alert>
              </v-card-text>
            </v-card>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" lg="4">
        <v-card outlined class="mb-4">
          <v-card-title>
            <v-icon left color="warning">
              mdi-alert
            </v-icon>
            Riesgo didáctico
          </v-card-title>
          <v-divider />
          <v-card-text>
            <p class="mb-2">
              Guardar el JWT en <strong>localStorage</strong> no es automáticamente inseguro, pero aumenta mucho el
              impacto de una XSS: cualquier JavaScript inyectado en la página puede leer ese token.
            </p>
            <p class="mb-0">
              En modo seguro preferimos mantener el token en <strong>memoria</strong> y, si el laboratorio lo necesita,
              usar una <strong>cookie HttpOnly</strong> con <strong>SameSite</strong> y <strong>Secure</strong>.
            </p>
          </v-card-text>
        </v-card>

        <v-card outlined>
          <v-card-title>
            <v-icon left color="secondary">
              mdi-book-open-page-variant
            </v-icon>
            Alternativas
          </v-card-title>
          <v-divider />
          <v-list dense>
            <v-list-item>
              <v-list-item-icon>
                <v-icon color="primary">mdi-memory</v-icon>
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>Token en memoria</v-list-item-title>
                <v-list-item-subtitle>Se pierde al recargar, pero limita el tiempo de exposición.</v-list-item-subtitle>
              </v-list-item-content>
            </v-list-item>
            <v-list-item>
              <v-list-item-icon>
                <v-icon color="success">mdi-cookie</v-icon>
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>Cookie HttpOnly</v-list-item-title>
                <v-list-item-subtitle>JavaScript no puede leerla directamente.</v-list-item-subtitle>
              </v-list-item-content>
            </v-list-item>
            <v-list-item>
              <v-list-item-icon>
                <v-icon color="info">mdi-shield-refresh</v-icon>
              </v-list-item-icon>
              <v-list-item-content>
                <v-list-item-title>Refresh token controlado</v-list-item-title>
                <v-list-item-subtitle>Útil si necesitas sesiones más largas sin exponer el access token.</v-list-item-subtitle>
              </v-list-item-content>
            </v-list-item>
          </v-list>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
const API_BASE_URL = process.env.VUE_APP_API_BASE_URL || 'http://localhost:8082/api'
const TOKEN_KEY = 'tfm_lab_jwt'

export default {
  name: 'TokenStorageLab',
  data () {
    return {
      browserOrigin: window.location.origin,
      form: {
        username: 'alice',
        password: 'password123'
      },
      useHttpOnlyCookie: false,
      loadingVulnerable: false,
      loadingSecure: false,
      loadingMe: false,
      memoryToken: '',
      localStorageToken: window.localStorage.getItem(TOKEN_KEY) || '',
      readTokenPreview: '',
      meResponse: null,
      message: '',
      error: ''
    }
  },
  created () {},
  methods: {
    emitAuthUpdate () {
      window.dispatchEvent(new Event('tfm-auth-updated'))
    },
    maskedToken (token) {
      if (!token) {
        return '-'
      }

      if (token.length <= 18) {
        return token
      }

      return `${token.slice(0, 12)}...${token.slice(-12)}`
    },
    setFeedback (message) {
      this.message = message
      this.error = ''
    },
    setError (message) {
      this.error = message
      this.message = ''
    },
    async loginVulnerable () {
      this.loadingVulnerable = true
      this.error = ''
      this.message = ''

      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/token-storage/login`, {
          username: this.form.username,
          password: this.form.password,
          deliveryMode: 'header'
        })

        this.memoryToken = ''
        this.readTokenPreview = ''
        this.localStorageToken = response.data.accessToken
        window.localStorage.setItem(TOKEN_KEY, response.data.accessToken)
        window.sessionStorage.setItem('tfm_lab_session_user', this.form.username)
        this.emitAuthUpdate()
        this.setFeedback('JWT guardado en localStorage. Cualquier JavaScript inyectado en la página podría leerlo.')
      } catch (error) {
        this.setError(this.extractError(error))
      } finally {
        this.loadingVulnerable = false
      }
    },
    readLocalStorageToken () {
      this.readTokenPreview = window.localStorage.getItem(TOKEN_KEY) || ''

      if (this.readTokenPreview) {
        this.setFeedback('Token leído desde localStorage con JavaScript normal de la página.')
      } else {
        this.setError('No hay token guardado en localStorage.')
      }
    },
    async loginSecure () {
      this.loadingSecure = true
      this.error = ''
      this.message = ''

      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/token-storage/login`, {
          username: this.form.username,
          password: this.form.password,
          deliveryMode: this.useHttpOnlyCookie ? 'cookie' : 'header'
        }, {
          withCredentials: this.useHttpOnlyCookie
        })

        this.localStorageToken = ''
        window.localStorage.removeItem(TOKEN_KEY)
        this.memoryToken = this.useHttpOnlyCookie ? '' : response.data.accessToken
        this.readTokenPreview = ''
        window.sessionStorage.setItem('tfm_lab_session_user', this.form.username)
        this.emitAuthUpdate()
        this.setFeedback(
          this.useHttpOnlyCookie
            ? 'Login seguro con cookie HttpOnly. El token no queda disponible para JavaScript.'
            : 'Login seguro con token en memoria. El token existe solo mientras la pestaña siga viva.'
        )
      } catch (error) {
        this.setError(this.extractError(error))
      } finally {
        this.loadingSecure = false
      }
    },
    async loadCurrentUser () {
      this.loadingMe = true
      this.error = ''
      this.message = ''

      try {
        const headers = {}
        const token = this.memoryToken || this.localStorageToken

        if (token) {
          headers.Authorization = `Bearer ${token}`
        }

        const response = await this.$http.get(`${API_BASE_URL}/lab/token-storage/me`, {
          headers,
          withCredentials: this.useHttpOnlyCookie
        })

        this.meResponse = response.data
        this.setFeedback('El backend validó el JWT y devolvió el usuario autenticado del laboratorio.')
      } catch (error) {
        this.meResponse = null
        this.setError(this.extractError(error))
      } finally {
        this.loadingMe = false
      }
    },
    logout () {
      this.memoryToken = ''
      this.localStorageToken = ''
      this.readTokenPreview = ''
      this.meResponse = null
      window.localStorage.removeItem(TOKEN_KEY)
      window.sessionStorage.removeItem('tfm_lab_session_user')
      this.emitAuthUpdate()
      this.setFeedback('Sesión cerrada. Ya puedes cambiar de usuario.')
    },
    extractError (error) {
      if (error.response && error.response.data) {
        if (typeof error.response.data === 'string') {
          return error.response.data
        }

        return error.response.data.message || error.response.data.error || `HTTP ${error.response.status}`
      }

      return 'No se pudo completar la operación.'
    }
  }
}
</script>

<style scoped>
.lab-page {
  min-height: calc(100vh - 64px);
  background: #f6f8fa;
  padding: 24px;
}

.lab-title {
  gap: 8px;
}

th {
  width: 180px;
  color: #374151;
}
</style>
