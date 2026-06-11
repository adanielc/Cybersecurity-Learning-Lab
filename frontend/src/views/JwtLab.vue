<template>
  <lab-page-shell
    title="JWT"
    icon="mdi-key-variant"
    description="Explora la diferencia entre leer claims en el cliente y validar la firma y expiración del token en servidor."
    vulnerable-endpoint="POST /api/lab/token-storage/login"
    secure-endpoint="GET /api/lab/token-storage/me"
    vulnerable-method="POST"
    secure-method="GET"
    vulnerable-hint="El cliente puede decodificar un JWT sin verificarlo, pero eso no prueba autenticidad."
    secure-hint="El servidor comprueba firma, expiración y propósito antes de aceptar el token."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="4">
          <v-text-field v-model="username" label="Username" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="4">
          <v-text-field v-model="password" label="Password" type="password" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="4">
          <v-select
            v-model="deliveryMode"
            :items="deliveryModes"
            label="Entrega"
            outlined
            dense
            hide-details="auto"
          />
        </v-col>
      </v-row>

      <v-row>
        <v-col cols="12" md="6">
          <v-btn block color="warning" :loading="loadingLogin" @click="issueToken">
            Login vulnerable
          </v-btn>
        </v-col>
        <v-col cols="12" md="6">
          <v-btn block color="success" :loading="loadingMe" @click="validateToken">
            Login seguro
          </v-btn>
        </v-col>
      </v-row>

      <v-textarea
        v-model="token"
        label="JWT emitido"
        outlined
        dense
        auto-grow
        rows="3"
        class="mt-4"
      />
    </template>

    <template #vulnerable-result>
      <v-alert v-if="loginMessage" :type="loginOk ? 'success' : 'error'" outlined dense>
        {{ loginMessage }}
      </v-alert>
      <pre class="json-box">{{ pretty(loginResult) }}</pre>
    </template>

    <template #secure-result>
      <v-alert v-if="meMessage" :type="meOk ? 'success' : 'error'" outlined dense>
        {{ meMessage }}
      </v-alert>
      <pre class="json-box">{{ pretty(meResult) }}</pre>
    </template>
  </lab-page-shell>
</template>

<script>
import LabPageShell from '../components/LabPageShell.vue'
import { DEFAULT_API_BASE_URL, apiMessage, apiPayload, prettyJson } from '../utils/labApi'

export default {
  name: 'JwtLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      username: 'alice',
      password: 'password123',
      deliveryMode: 'header',
      deliveryModes: ['header', 'cookie'],
      token: '',
      loginResult: null,
      meResult: null,
      loginMessage: '',
      meMessage: '',
      loginOk: false,
      meOk: false,
      loadingLogin: false,
      loadingMe: false,
      remediationPoints: [
        'Validar firma y expiración en servidor.',
        'No confiar en claims sin verificar el token completo.',
        'Mantener la duración corta del access token.'
      ],
      sideBullets: [
        'Un JWT es solo una estructura firmada; si se acepta sin verificar, el contenido puede ser manipulado.',
        'El cliente puede leer claims, pero la decisión de acceso siempre debe hacerse en servidor.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async issueToken () {
      this.loadingLogin = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/token-storage/login`, {
          username: this.username,
          password: this.password,
          deliveryMode: this.deliveryMode
        })
        this.loginResult = response.data
        this.token = response.data.accessToken || ''
        this.loginMessage = 'El backend emitió un JWT de laboratorio.'
        this.loginOk = true
      } catch (error) {
        this.loginResult = apiPayload(error)
        this.loginMessage = apiMessage(error)
        this.loginOk = false
      } finally {
        this.loadingLogin = false
      }
    },
    async validateToken () {
      this.loadingMe = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/token-storage/me`, {
          headers: this.token.trim() ? { Authorization: `Bearer ${this.token.trim()}` } : {}
        })
        this.meResult = response.data
        this.meMessage = 'El backend validó la firma, la expiración y el propósito del token.'
        this.meOk = true
      } catch (error) {
        this.meResult = apiPayload(error)
        this.meMessage = apiMessage(error)
        this.meOk = false
      } finally {
        this.loadingMe = false
      }
    }
  }
}
</script>

<style scoped>
.json-box {
  background: #0f172a;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  min-height: 120px;
}
</style>
