<template>
  <lab-page-shell
    title="SQL Injection"
    icon="mdi-database-search"
    description="Comparativa entre una búsqueda vulnerable a SQL Injection y otra protegida con consultas parametrizadas."
    vulnerable-endpoint="GET /api/lab/sqli/users/search?username=valor"
    secure-endpoint="GET /api/lab/sqli/users/search-secure?username=valor"
    vulnerable-hint="La consulta vulnerable concatena el parámetro directamente y permite payloads como ' OR '1'='1."
    secure-hint="La consulta segura usa parámetros y trata la entrada como texto literal."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="8">
          <v-text-field
            v-model="username"
            label="Username"
            outlined
            dense
            hide-details="auto"
          />
        </v-col>
        <v-col cols="12" md="4" class="d-flex align-center">
          <v-btn block color="warning" class="mr-2" :loading="loadingVulnerable" @click="searchVulnerable">
            Buscar vulnerable
          </v-btn>
        </v-col>
      </v-row>
      <v-row>
        <v-col cols="12" md="4" offset-md="8">
          <v-btn block color="success" :loading="loadingSecure" @click="searchSecure">
            Buscar seguro
          </v-btn>
        </v-col>
      </v-row>

      <v-alert type="info" outlined dense class="mt-4">
        Payloads sugeridos: <code>' OR '1'='1</code>, <code>admin' --</code>
      </v-alert>
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
  name: 'SqliLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      username: 'alice',
      loadingVulnerable: false,
      loadingSecure: false,
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'Usar consultas parametrizadas o JPA seguro.',
        'Validar y normalizar parámetros de entrada.',
        'Aplicar el mínimo privilegio en la cuenta de base de datos.'
      ],
      sideBullets: [
        'El ataque funciona porque la entrada se mezcla con SQL.',
        'El modo seguro trata el payload como dato, no como código.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async searchVulnerable () {
      this.loadingVulnerable = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/sqli/users/search`, {
          params: { username: this.username }
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La búsqueda vulnerable respondió con los datos devueltos por la consulta concatenada.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loadingVulnerable = false
      }
    },
    async searchSecure () {
      this.loadingSecure = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/sqli/users/search-secure`, {
          params: { username: this.username }
        })
        this.secureResult = response.data
        this.secureMessage = 'La búsqueda segura usa parámetros y no interpreta el payload.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loadingSecure = false
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
