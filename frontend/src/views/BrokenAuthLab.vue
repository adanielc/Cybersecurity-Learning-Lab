<template>
  <v-container fluid class="lab-page">
    <v-row>
      <v-col cols="12" lg="8">
        <v-card outlined>
          <v-card-title class="lab-title">
            <v-icon left color="primary">
              mdi-lock-alert
            </v-icon>
            Broken Authentication
            <v-spacer />
            <v-chip small color="warning" text-color="black">
              LAB
            </v-chip>
          </v-card-title>

          <v-divider />

          <v-card-text>
            <v-alert type="info" outlined dense>
              El objetivo es comparar una autenticación que filtra información con otra que responde con mensajes genéricos
              y aplica una política de contraseñas y defensa frente a fuerza bruta.
            </v-alert>

            <v-row>
              <v-col cols="12" md="6">
                <v-card outlined class="mb-4">
                  <v-card-title class="subtitle-1">
                    Login
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <v-text-field v-model="login.username" label="Username" outlined dense />
                    <v-text-field v-model="login.password" label="Password" type="password" outlined dense />
                    <v-row>
                      <v-col cols="12" sm="6">
                        <v-btn block color="warning" :loading="loading.insecureLogin" @click="loginInsecure">
                          Login vulnerable
                        </v-btn>
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-btn block color="success" :loading="loading.secureLogin" @click="loginSecure">
                          Login seguro
                        </v-btn>
                      </v-col>
                    </v-row>
                  </v-card-text>
                </v-card>
              </v-col>

              <v-col cols="12" md="6">
                <v-card outlined class="mb-4">
                  <v-card-title class="subtitle-1">
                    Registro
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <v-text-field v-model="register.username" label="Username" outlined dense />
                    <v-text-field v-model="register.displayName" label="Display name" outlined dense />
                    <v-text-field v-model="register.email" label="Email" outlined dense />
                    <v-text-field v-model="register.password" label="Password" type="password" outlined dense />
                    <v-row>
                      <v-col cols="12" sm="6">
                        <v-btn block color="warning" :loading="loading.insecureRegister" @click="registerInsecure">
                          Registro vulnerable
                        </v-btn>
                      </v-col>
                      <v-col cols="12" sm="6">
                        <v-btn block color="success" :loading="loading.secureRegister" @click="registerSecure">
                          Registro seguro
                        </v-btn>
                      </v-col>
                    </v-row>
                  </v-card-text>
                </v-card>
              </v-col>
            </v-row>

            <v-row>
              <v-col cols="12" md="6">
                <v-card outlined>
                  <v-card-title class="subtitle-2">
                    Respuesta vulnerable
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <v-alert v-if="insecureResult" :type="insecureResult.success ? 'success' : 'error'" outlined dense>
                      {{ insecureResult.message }}
                    </v-alert>
                    <v-simple-table v-if="insecureResult">
                      <tbody>
                        <tr><th>Usuario</th><td>{{ insecureResult.username || '-' }}</td></tr>
                        <tr><th>Email</th><td>{{ insecureResult.email || '-' }}</td></tr>
                        <tr><th>Rol</th><td>{{ insecureResult.role || '-' }}</td></tr>
                        <tr><th>Token</th><td>{{ masked(insecureResult.token) }}</td></tr>
                      </tbody>
                    </v-simple-table>
                    <div v-else class="text--secondary">
                      Aun no se ha lanzado una prueba vulnerable.
                    </div>
                  </v-card-text>
                </v-card>
              </v-col>

              <v-col cols="12" md="6">
                <v-card outlined>
                  <v-card-title class="subtitle-2">
                    Respuesta segura
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <v-alert v-if="secureResult" :type="secureResult.success ? 'success' : 'error'" outlined dense>
                      {{ secureResult.message }}
                    </v-alert>
                    <v-simple-table v-if="secureResult">
                      <tbody>
                        <tr><th>Usuario</th><td>{{ secureResult.username || '-' }}</td></tr>
                        <tr><th>Email</th><td>{{ secureResult.email || '-' }}</td></tr>
                        <tr><th>Rol</th><td>{{ secureResult.role || '-' }}</td></tr>
                        <tr><th>Token</th><td>{{ masked(secureResult.token) }}</td></tr>
                      </tbody>
                    </v-simple-table>
                    <div v-else class="text--secondary">
                      Aun no se ha lanzado una prueba segura.
                    </div>
                  </v-card-text>
                </v-card>
              </v-col>
            </v-row>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" lg="4">
        <v-card outlined class="mb-4">
          <v-card-title>
            <v-icon left color="warning">
              mdi-alert
            </v-icon>
            Enumeracion
          </v-card-title>
          <v-divider />
          <v-card-text>
            <p class="mb-2">
              En la version vulnerable, el backend puede devolver "usuario no encontrado" o "contrasena incorrecta", lo
              que facilita probar nombres de cuenta existentes.
            </p>
            <p class="mb-0">
              En la version segura, los errores son genericos y el atacante no recibe una pista util sobre la existencia
              del usuario.
            </p>
          </v-card-text>
        </v-card>

        <v-card outlined>
          <v-card-title>
            <v-icon left color="secondary">
              mdi-book-lock
            </v-icon>
            Reglas seguras
          </v-card-title>
          <v-divider />
          <v-list dense>
            <v-list-item>
              <v-list-item-content>
                <v-list-item-title>Contraseñas minimas fuertes</v-list-item-title>
                <v-list-item-subtitle>Longitud, mayusculas, minusculas, digitos y simbolos.</v-list-item-subtitle>
              </v-list-item-content>
            </v-list-item>
            <v-list-item>
              <v-list-item-content>
                <v-list-item-title>Hashing seguro</v-list-item-title>
                <v-list-item-subtitle>BCrypt para evitar almacenamiento en texto plano.</v-list-item-subtitle>
              </v-list-item-content>
            </v-list-item>
            <v-list-item>
              <v-list-item-content>
                <v-list-item-title>Mensajes genericos</v-list-item-title>
                <v-list-item-subtitle>No se revela si existe el usuario o que fallo exactamente.</v-list-item-subtitle>
              </v-list-item-content>
            </v-list-item>
            <v-list-item>
              <v-list-item-content>
                <v-list-item-title>Fuerza bruta</v-list-item-title>
                <v-list-item-subtitle>Rate limiting para frenar intentos repetidos en login seguro.</v-list-item-subtitle>
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

export default {
  name: 'BrokenAuthLab',
  data () {
    return {
      login: {
        username: 'alice',
        password: 'password123'
      },
      register: {
        username: '',
        displayName: '',
        email: '',
        password: ''
      },
      loading: {
        insecureLogin: false,
        secureLogin: false,
        insecureRegister: false,
        secureRegister: false
      },
      insecureResult: null,
      secureResult: null
    }
  },
  methods: {
    masked (token) {
      if (!token) {
        return '-'
      }

      if (token.length <= 18) {
        return token
      }

      return `${token.slice(0, 12)}...${token.slice(-12)}`
    },
    async loginInsecure () {
      this.loading.insecureLogin = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/login-insecure`, this.login)
        this.insecureResult = response.data
      } catch (error) {
        this.insecureResult = this.extractResult(error)
      } finally {
        this.loading.insecureLogin = false
      }
    },
    async loginSecure () {
      this.loading.secureLogin = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/login-secure`, this.login)
        this.secureResult = response.data
      } catch (error) {
        this.secureResult = this.extractResult(error)
      } finally {
        this.loading.secureLogin = false
      }
    },
    async registerInsecure () {
      this.loading.insecureRegister = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/register-insecure`, this.register)
        this.insecureResult = response.data
      } catch (error) {
        this.insecureResult = this.extractResult(error)
      } finally {
        this.loading.insecureRegister = false
      }
    },
    async registerSecure () {
      this.loading.secureRegister = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/register-secure`, this.register)
        this.secureResult = response.data
      } catch (error) {
        this.secureResult = this.extractResult(error)
      } finally {
        this.loading.secureRegister = false
      }
    },
    extractResult (error) {
      if (error.response) {
        return {
          success: false,
          message: (error.response.data && error.response.data.message) || `HTTP ${error.response.status}`,
          token: '',
          username: '',
          email: '',
          displayName: '',
          role: '',
          mode: ''
        }
      }

      return {
        success: false,
        message: 'No se pudo completar la operacion.',
        token: '',
        username: '',
        email: '',
        displayName: '',
        role: '',
        mode: ''
      }
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
  width: 120px;
  color: #374151;
}
</style>
