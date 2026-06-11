<template>
  <lab-page-shell
    title="Cross-Site Scripting"
    icon="mdi-code-tags"
    description="Compara un comentario renderizado como HTML sin sanitizar con una versión segura que lo trata como texto."
    vulnerable-endpoint="POST /api/lab/xss/comments | GET /api/lab/xss/comments"
    secure-endpoint="POST /api/lab/xss/comments-secure | GET /api/lab/xss/comments-secure"
    vulnerable-method="POST / GET"
    secure-method="POST / GET"
    vulnerable-hint="La versión vulnerable guarda y renderiza el contenido tal cual."
    secure-hint="La versión segura sanitiza o escapa antes de renderizar."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
  >
    <template #form>
      <v-row>
        <v-col cols="12" md="4">
          <v-text-field v-model="author" label="Autor" outlined dense hide-details="auto" />
        </v-col>
        <v-col cols="12" md="8">
          <v-text-field v-model="content" label="Contenido" outlined dense hide-details="auto" />
        </v-col>
      </v-row>

      <v-row>
        <v-col cols="12" md="4">
          <v-btn block color="warning" class="mb-2" :loading="loading.vulnerablePost" @click="postVulnerable">
            Publicar vulnerable
          </v-btn>
          <v-btn block color="warning" outlined :loading="loading.vulnerableGet" @click="getVulnerable">
            Cargar vulnerable
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-btn block color="success" class="mb-2" :loading="loading.securePost" @click="postSecure">
            Publicar seguro
          </v-btn>
          <v-btn block color="success" outlined :loading="loading.secureGet" @click="getSecure">
            Cargar seguro
          </v-btn>
        </v-col>
        <v-col cols="12" md="4">
          <v-alert type="info" outlined dense>
            Payload: <code>&lt;img src=x onerror=alert('XSS laboratorio')&gt;</code>
          </v-alert>
        </v-col>
      </v-row>
    </template>

    <template #vulnerable-result>
      <v-alert v-if="vulnerableMessage" :type="vulnerableOk ? 'success' : 'error'" outlined dense>
        {{ vulnerableMessage }}
      </v-alert>
      <div v-if="vulnerableResult && vulnerableResult.length" class="preview-box">
        <div v-for="comment in vulnerableResult" :key="comment.id" class="comment-card">
          <div class="comment-meta">{{ comment.author }} - {{ comment.createdAt }}</div>
          <div v-html="comment.content" />
        </div>
      </div>
      <pre class="json-box">{{ pretty(vulnerableResult) }}</pre>
    </template>

    <template #secure-result>
      <v-alert v-if="secureMessage" :type="secureOk ? 'success' : 'error'" outlined dense>
        {{ secureMessage }}
      </v-alert>
      <div v-if="secureResult && secureResult.length" class="preview-box">
        <div v-for="comment in secureResult" :key="comment.id" class="comment-card">
          <div class="comment-meta">{{ comment.author }} - {{ comment.createdAt }}</div>
          <div>{{ comment.content }}</div>
        </div>
      </div>
      <pre class="json-box">{{ pretty(secureResult) }}</pre>
    </template>
  </lab-page-shell>
</template>

<script>
import LabPageShell from '../components/LabPageShell.vue'
import { DEFAULT_API_BASE_URL, apiMessage, apiPayload, prettyJson } from '../utils/labApi'

export default {
  name: 'XssLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      author: 'alice',
      content: "<img src=x onerror=alert('XSS laboratorio')>",
      loading: {
        vulnerablePost: false,
        vulnerableGet: false,
        securePost: false,
        secureGet: false
      },
      vulnerableResult: [],
      secureResult: [],
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      remediationPoints: [
        'Sanitizar o escapar el contenido antes de renderizar.',
        'Evitar v-html con contenido de usuario.',
        'Aplicar CSP como defensa en profundidad.'
      ],
      sideBullets: [
        'XSS almacenado: el payload queda persistido y se sirve a otros usuarios.',
        'XSS reflejado: el payload viaja en la petición y se refleja en la respuesta.'
      ]
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async postVulnerable () {
      this.loading.vulnerablePost = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/xss/comments`, {
          author: this.author,
          content: this.content
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El comentario se guardó y podrá renderizar HTML sin sanitizar.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerablePost = false
      }
    },
    async getVulnerable () {
      this.loading.vulnerableGet = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/xss/comments`)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La ruta vulnerable devuelve el contenido tal cual.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerableGet = false
      }
    },
    async postSecure () {
      this.loading.securePost = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/xss/comments-secure`, {
          author: this.author,
          content: this.content
        })
        this.secureResult = response.data
        this.secureMessage = 'El comentario seguro se sanitiza o se escapa.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.securePost = false
      }
    },
    async getSecure () {
      this.loading.secureGet = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/xss/comments-secure`)
        this.secureResult = response.data
        this.secureMessage = 'La ruta segura devuelve contenido neutralizado.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secureGet = false
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

.preview-box {
  margin-bottom: 16px;
}

.comment-card {
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  padding: 12px;
  margin-bottom: 12px;
}

.comment-meta {
  font-size: 0.8rem;
  color: #64748b;
  margin-bottom: 6px;
}
</style>
