<template>
  <lab-page-shell
    title="NoSQL Injection"
    icon="mdi-database"
    description="Demostración de cómo aceptar JSON arbitrario en MongoDB puede convertir operadores como $ne o $regex en lógica de consulta."
    vulnerable-endpoint="POST /api/lab/nosqli/login | POST /api/lab/nosqli/search-comments"
    secure-endpoint="POST /api/lab/nosqli/login-secure | POST /api/lab/nosqli/search-comments-secure"
    vulnerable-method="POST"
    secure-method="POST"
    vulnerable-hint="La versión vulnerable acepta un objeto JSON libre y lo pasa a la query documental."
    secure-hint="La versión segura usa DTOs tipados y rechaza operadores MongoDB peligrosos."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">Login documental</v-card-title>
        <v-divider />
        <v-card-text>
          <v-row>
            <v-col cols="12" md="6">
              <v-textarea
                v-model="vulnerableLoginJson"
                label="Body vulnerable (JSON arbitrario)"
                outlined
                dense
                auto-grow
                rows="6"
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="6">
              <v-text-field v-model="secureLogin.username" label="Username seguro" outlined dense />
              <v-text-field v-model="secureLogin.password" label="Password seguro" type="password" outlined dense />
              <v-btn block color="success" class="mb-2" :loading="loading.secureLogin" @click="loginSecure">
                Login seguro
              </v-btn>
              <v-btn block color="warning" outlined :loading="loading.vulnerableLogin" @click="loginVulnerable">
                Login vulnerable
              </v-btn>
            </v-col>
          </v-row>
          <v-alert type="info" outlined dense class="mt-2">
            Ejemplo educativo: <code>{ "username": { "$ne": null }, "password": { "$ne": null } }</code>
          </v-alert>
        </v-card-text>
      </v-card>

      <v-card outlined>
        <v-card-title class="subtitle-2">Búsqueda de comentarios</v-card-title>
        <v-divider />
        <v-card-text>
          <v-row>
            <v-col cols="12" md="6">
              <v-textarea
                v-model="vulnerableCommentsJson"
                label="Body vulnerable (JSON arbitrario)"
                outlined
                dense
                auto-grow
                rows="6"
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="6">
              <v-text-field v-model="secureComments.text" label="Texto seguro" outlined dense />
              <v-btn block color="success" class="mb-2" :loading="loading.secureComments" @click="searchCommentsSecure">
                Buscar comentarios seguro
              </v-btn>
              <v-btn block color="warning" outlined :loading="loading.vulnerableComments" @click="searchCommentsVulnerable">
                Buscar comentarios vulnerable
              </v-btn>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>
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
  name: 'NoSqlInjectionLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      loading: {
        vulnerableLogin: false,
        secureLogin: false,
        vulnerableComments: false,
        secureComments: false
      },
      vulnerableLoginJson: '{\n  "username": { "$ne": null },\n  "password": { "$ne": null }\n}',
      vulnerableCommentsJson: '{\n  "text": { "$regex": ".*" }\n}',
      secureLogin: {
        username: 'alice',
        password: 'password123'
      },
      secureComments: {
        text: 'buenas'
      },
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'Usar DTOs tipados y validación estricta.',
        'Rechazar operadores MongoDB como $ne, $gt, $regex o $where.',
        'Nunca pasar JSON arbitrario directamente a la query.'
      ],
      sideBullets: [
        'El riesgo aparece cuando la entrada se trata como parte de la consulta documental.',
        'El modo seguro solo acepta cadenas y tipos esperados.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    parseJson (value) {
      return JSON.parse(value)
    },
    async loginVulnerable () {
      this.loading.vulnerableLogin = true
      try {
        const payload = this.parseJson(this.vulnerableLoginJson)
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/login`, payload)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El endpoint vulnerable aceptó JSON arbitrario.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerableLogin = false
      }
    },
    async loginSecure () {
      this.loading.secureLogin = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/login-secure`, this.secureLogin)
        this.secureResult = response.data
        this.secureMessage = 'El endpoint seguro solo acepta DTOs tipados.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secureLogin = false
      }
    },
    async searchCommentsVulnerable () {
      this.loading.vulnerableComments = true
      try {
        const payload = this.parseJson(this.vulnerableCommentsJson)
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/search-comments`, payload)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La búsqueda vulnerable procesó el body sin restringir operadores.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerableComments = false
      }
    },
    async searchCommentsSecure () {
      this.loading.secureComments = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/search-comments-secure`, this.secureComments)
        this.secureResult = response.data
        this.secureMessage = 'La búsqueda segura rechaza operadores MongoDB y valida tipos.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secureComments = false
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
