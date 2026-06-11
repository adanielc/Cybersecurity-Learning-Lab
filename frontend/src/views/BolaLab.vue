<template>
  <lab-page-shell
    title="BOLA / IDOR"
    icon="mdi-account-key"
    description="Demostración de Broken Object Level Authorization: manipular un ID en la URL no debe permitir leer el objeto de otro usuario."
    vulnerable-endpoint="GET /api/lab/bola/profile/{userId}"
    secure-endpoint="GET /api/lab/bola/profile-secure/{userId} | GET /api/lab/bola/my-profile"
    vulnerable-hint="La versión vulnerable devuelve cualquier perfil solicitado sin comprobar ownership."
    secure-hint="La versión segura compara el usuario autenticado con el recurso y devuelve 403 si no corresponde."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="4">
          <v-text-field v-model="authToken" label="JWT" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="4">
          <v-text-field v-model="myUserId" label="Mi userId" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="4">
          <v-text-field v-model="targetUserId" label="userId objetivo" outlined dense hide-details="auto" />
        </v-col>
      </v-row>

      <v-row>
        <v-col cols="12" md="4">
          <v-btn block color="warning" :loading="loading.vulnerable" @click="loadVulnerableProfile">
            Consultar vulnerable
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block color="success" :loading="loading.secure" @click="loadSecureProfile">
            Consultar seguro
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block outlined color="primary" :loading="loading.mine" @click="loadMyProfile">
            Mi perfil
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
  name: 'BolaLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      authToken: '',
      myUserId: '2',
      targetUserId: '1',
      loading: {
        vulnerable: false,
        secure: false,
        mine: false
      },
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'Verificar ownership en servidor, no solo en frontend.',
        'Aplicar control de acceso por rol y por recurso.',
        'Ocultar campos sensibles en DTOs públicos.'
      ],
      sideBullets: [
        'Un ID en URL no es una prueba de autorización.',
        'El modo seguro debe devolver 403 cuando el recurso no pertenece al usuario autenticado.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    headers () {
      return this.authToken.trim()
        ? { Authorization: `Bearer ${this.authToken.trim()}` }
        : {}
    },
    async loadVulnerableProfile () {
      this.loading.vulnerable = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/bola/profile/${encodeURIComponent(this.targetUserId)}`, {
          headers: this.headers()
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El endpoint vulnerable devolvió el recurso solo por ID.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerable = false
      }
    },
    async loadSecureProfile () {
      this.loading.secure = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/bola/profile-secure/${encodeURIComponent(this.targetUserId)}`, {
          headers: this.headers()
        })
        this.secureResult = response.data
        this.secureMessage = 'El endpoint seguro validó ownership o rol ADMIN.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secure = false
      }
    },
    async loadMyProfile () {
      this.loading.mine = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/bola/my-profile`, {
          headers: this.headers()
        })
        this.secureResult = response.data
        this.secureMessage = 'Este es el perfil autenticado devuelto por el backend.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.mine = false
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
