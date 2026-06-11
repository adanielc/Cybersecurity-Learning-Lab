<template>
  <lab-page-shell
    title="CORS"
    icon="mdi-origin"
    description="Observa cómo una política CORS demasiado permisiva puede permitir lectura desde orígenes no previstos."
    vulnerable-endpoint="GET /api/lab/cors/public-data | GET /api/lab/cors/private-data"
    secure-endpoint="GET /api/lab/cors/secure-private-data"
    vulnerable-hint="La configuración vulnerable permite orígenes y cabeceras demasiado amplios."
    secure-hint="La configuración segura limita origen, métodos y cabeceras al mínimo necesario."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="6">
          <v-text-field :value="browserOrigin" label="Origen actual" outlined dense readonly />
        </v-col>
        <v-col cols="12" md="6">
          <v-text-field v-model="originHint" label="Origen de prueba" outlined dense />
        </v-col>
      </v-row>

      <v-row>
        <v-col cols="12" md="4">
          <v-btn block color="warning" :loading="loading.publicData" @click="loadPublicData">
            Pública vulnerable
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block color="warning" outlined :loading="loading.privateData" @click="loadPrivateData">
            Privada vulnerable
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block color="success" :loading="loading.securePrivateData" @click="loadSecurePrivateData">
            Privada segura
          </v-btn>
        </v-col>
      </v-row>
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
  name: 'CorsLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      browserOrigin: window.location.origin,
      originHint: window.location.origin,
      loading: {
        publicData: false,
        privateData: false,
        securePrivateData: false
      },
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'Permitir solo el origen legítimo del frontend.',
        'Limitar métodos y cabeceras a lo estrictamente necesario.',
        'Recordar que CORS no sustituye autenticación ni autorización.'
      ],
      sideBullets: [
        'allowedOrigins("*") en APIs sensibles amplía la superficie de exposición.',
        'Una política CORS correcta sigue necesitando controles de acceso reales.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async loadPublicData () {
      this.loading.publicData = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/cors/public-data`)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La lectura pública está permitida.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.publicData = false
      }
    },
    async loadPrivateData () {
      this.loading.privateData = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/cors/private-data`)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La política vulnerable permitió la lectura.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.privateData = false
      }
    },
    async loadSecurePrivateData () {
      this.loading.securePrivateData = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/cors/secure-private-data`)
        this.secureResult = response.data
        this.secureMessage = 'La política segura mantuvo el acceso bajo control.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.securePrivateData = false
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
