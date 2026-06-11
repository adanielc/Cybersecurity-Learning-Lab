<template>
  <lab-page-shell
    title="Excessive Data Exposure"
    icon="mdi-eye"
    description="Compara la devolución de una entidad completa frente a un DTO público con solo la información necesaria."
    vulnerable-endpoint="GET /api/lab/exposure/users/{id} | GET /api/lab/exposure/users"
    secure-endpoint="GET /api/lab/exposure/users-secure/{id}"
    vulnerable-hint="La respuesta vulnerable devuelve campos internos y sensibles."
    secure-hint="La respuesta segura publica solo id, username y nombre visible."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="8">
          <v-text-field v-model="userId" label="User ID" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block color="warning" class="mb-2" :loading="loading.vulnerable" @click="loadVulnerable">
            Vulnerable
          </v-btn>
          <v-btn block color="success" :loading="loading.secure" @click="loadSecure">
            Seguro
          </v-btn>
        </v-col>
      </v-row>
      <v-btn block outlined color="primary" class="mt-2" :loading="loading.list" @click="loadList">
        Listado vulnerable
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
  name: 'DataExposureLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      userId: '1',
      loading: {
        vulnerable: false,
        secure: false,
        list: false
      },
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'No devolver entidades JPA directamente.',
        'Diseñar DTOs públicos con mínima exposición.',
        'Revisar serialización para ocultar campos internos.'
      ],
      sideBullets: [
        'Ocultar campos en frontend no corrige el problema si el backend ya los envió.',
        'El principio de mínima exposición reduce el impacto de una fuga accidental.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async loadVulnerable () {
      this.loading.vulnerable = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users/${encodeURIComponent(this.userId)}`)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La entidad completa fue expuesta por el backend.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerable = false
      }
    },
    async loadSecure () {
      this.loading.secure = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users-secure/${encodeURIComponent(this.userId)}`)
        this.secureResult = response.data
        this.secureMessage = 'El DTO público limitó la exposición de datos.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secure = false
      }
    },
    async loadList () {
      this.loading.list = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users`)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El listado vulnerable devolvió demasiada información.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.list = false
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
