<template>
  <lab-page-shell
    title="Rate Limiting"
    icon="mdi-timer-sand"
    description="Compara un login sin límite de intentos frente a otro protegido con límite temporal y respuesta HTTP 429."
    vulnerable-endpoint="POST /api/lab/rate-limit/login-insecure"
    secure-endpoint="POST /api/lab/rate-limit/login-secure"
    vulnerable-method="POST"
    secure-method="POST"
    vulnerable-hint="La versión vulnerable permite fuerza bruta sin freno."
    secure-hint="La versión segura limita intentos por minuto y devuelve 429 al superar el umbral."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="6">
          <v-text-field v-model="username" label="Username" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="6">
          <v-text-field v-model="password" label="Password" type="password" outlined dense hide-details="auto" />
        </v-col>
      </v-row>

      <v-row>
        <v-col cols="12" md="4">
          <v-btn block color="warning" :loading="loading.vulnerable" @click="loginVulnerable">
            Login vulnerable
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block color="success" :loading="loading.secure" @click="loginSecure">
            Login seguro
          </v-btn>
        </v-col>
      </v-row>

      <v-btn block class="mt-2" outlined color="error" :loading="loading.batch" @click="runBatch">
        Lanzar varios intentos manuales
      </v-btn>
    </template>

    <template #vulnerable-result>
      <v-alert v-if="vulnerableMessage" :type="vulnerableOk ? 'success' : 'error'" outlined dense>
        {{ vulnerableMessage }}
      </v-alert>
      <pre class="json-box">{{ pretty(vulnerableResult) }}</pre>
    </template>

    <template #secure-result>
      <v-alert v-if="secureMessage" :type="secureOk ? 'success' : 'error'" outlined dense>
        {{ secureMessage }}
      </v-alert>
      <pre class="json-box">{{ pretty(secureResult) }}</pre>
    </template>
  </lab-page-shell>
</template>

<script>
import LabPageShell from '../components/LabPageShell.vue'
import { DEFAULT_API_BASE_URL, apiMessage, apiPayload, prettyJson } from '../utils/labApi'

export default {
  name: 'RateLimitLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      username: 'alice',
      password: 'wrong',
      loading: {
        vulnerable: false,
        secure: false,
        batch: false
      },
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'Limitar intentos por IP o por usuario.',
        'Combinar rate limiting con MFA y alertas.',
        'No bloquear de forma permanente en el laboratorio.'
      ],
      sideBullets: [
        'La fuerza bruta depende de poder repetir intentos rápido.',
        'HTTP 429 ayuda a cortar automatizaciones simples.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async loginVulnerable () {
      this.loading.vulnerable = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-insecure`, {
          username: this.username,
          password: this.password
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El login vulnerable no limita los intentos.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerable = false
      }
    },
    async loginSecure () {
      this.loading.secure = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-secure`, {
          username: this.username,
          password: this.password
        })
        this.secureResult = response.data
        this.secureMessage = 'El login seguro aplicó el control de intentos.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secure = false
      }
    },
    async runBatch () {
      this.loading.batch = true
      try {
        const attempts = []
        for (let i = 0; i < 6; i += 1) {
          try {
            const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-secure`, {
              username: this.username,
              password: this.password
            })
            attempts.push({ attempt: i + 1, status: response.status, body: response.data })
          } catch (error) {
            attempts.push({ attempt: i + 1, status: error.response ? error.response.status : 'ERR', body: apiPayload(error) })
          }
        }
        this.secureResult = attempts
        this.secureMessage = 'La tanda de intentos permite observar el HTTP 429 cuando corresponde.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.batch = false
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
