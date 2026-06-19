<template>
  <lab-page-shell
    title="NoSQL Injection"
    icon="mdi-database"
    description="Una NoSQL Injection aparece cuando el backend acepta JSON arbitrario y lo convierte directamente en una query documental. Aquí se comparan dos escenarios: login y búsqueda de comentarios en MongoDB."
    vulnerable-endpoint="POST /api/lab/nosqli/login | POST /api/lab/nosqli/search-comments"
    secure-endpoint="POST /api/lab/nosqli/login-secure | POST /api/lab/nosqli/search-comments-secure"
    vulnerable-method="POST"
    secure-method="POST"
    vulnerable-hint="La versión vulnerable acepta operadores MongoDB desde el body y cambia el significado de la consulta."
    secure-hint="La versión segura usa DTOs tipados y construye la query en el backend."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="Aquí la clave no es GET o POST. El riesgo aparece cuando el backend convierte el JSON del cliente en una query MongoDB sin controlar operadores como $ne, $regex o $where."
    owasp-label="OWASP A03: Injection"
    risk-label="Impacto alto: bypass de login, lectura no prevista y abuso de filtros"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué pasa por detrás</div>
          <p class="mini-text">
            El backend recibe un body JSON y lo transforma en una query documental. Si ese JSON contiene operadores
            MongoDB, la base de datos no lo trata como un valor normal, sino como parte de la lógica del filtro.
          </p>
        </div>

        <div>
          <div class="mini-title">Login vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ loginVulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Búsqueda vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ commentsVulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>En login puede autenticarse sin credenciales exactas usando operadores como <code>$ne</code>.</li>
            <li>En búsquedas puede ampliarse el filtro y mostrar documentos no previstos.</li>
            <li>El problema nace cuando el backend delega la estructura de la query al cliente.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué cambia</div>
          <p class="mini-text">
            En la versión segura el backend no acepta una query completa desde el cliente. Solo recibe campos esperados
            y construye internamente el filtro con tipos y criterios concretos.
          </p>
        </div>

        <div>
          <div class="mini-title">Login seguro</div>
          <pre class="sql-box sql-box--safe">{{ loginSecurePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Búsqueda segura</div>
          <pre class="sql-box sql-box--safe">{{ commentsSecurePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>El body ya no define la query completa.</li>
            <li>Operadores peligrosos quedan fuera del contrato del endpoint.</li>
            <li>La consulta mantiene la intención original del backend.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #form>
      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Dónde suele aparecer
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="context-grid">
            <div v-for="item in commonPlaces" :key="item.title" class="context-item">
              <div class="context-item__title">{{ item.title }}</div>
              <div class="context-item__text">{{ item.text }}</div>
            </div>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Código del backend
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: POST de login documental</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ loginVulnerableCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ loginSecureCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: POST de búsqueda de comentarios</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ commentsVulnerableCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ commentsSecureCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: POST de login documental
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            En este caso el atacante no inyecta texto dentro de una sentencia SQL, sino operadores MongoDB dentro del
            body JSON. Si el backend acepta ese JSON como query, la validación de credenciales cambia de significado.
          </p>

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
              <v-text-field
                v-model="secureLogin.username"
                label="Username seguro"
                outlined
                dense
                hide-details="auto"
              />
              <v-text-field
                v-model="secureLogin.password"
                label="Password seguro"
                type="password"
                outlined
                dense
                hide-details="auto"
              />
              <div class="payload-actions">
                <v-btn
                  v-for="item in loginPayloads"
                  :key="item.label"
                  small
                  outlined
                  color="primary"
                  class="mr-2 mb-2"
                  @click="setLoginPayload(item)"
                >
                  {{ item.label }}
                </v-btn>
              </div>
            </v-col>
          </v-row>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableLogin" @click="loginVulnerable">
                Ejecutar POST vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureLogin" @click="loginSecure">
                Ejecutar POST seguro
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Resultado vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="loginVulnerableMessage" :type="loginVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ loginVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ loginVulnerablePreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ loginVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(loginVulnerableResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Resultado seguro
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="loginSecureMessage" :type="loginSecureOk ? 'success' : 'error'" outlined dense>
                    {{ loginSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ loginSecurePreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ loginSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(loginSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: POST de búsqueda de comentarios
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aquí el cliente no debería definir una query MongoDB completa. Si envía operadores como <code>$regex</code>
            o <code>$ne</code>, el backend puede terminar mostrando comentarios que no pertenecían al caso de uso esperado.
          </p>

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
              <v-text-field
                v-model="secureComments.text"
                label="Texto seguro"
                outlined
                dense
                hide-details="auto"
              />
              <div class="payload-actions">
                <v-btn
                  v-for="item in commentPayloads"
                  :key="item.label"
                  small
                  outlined
                  color="primary"
                  class="mr-2 mb-2"
                  @click="setCommentPayload(item)"
                >
                  {{ item.label }}
                </v-btn>
              </div>
            </v-col>
          </v-row>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableComments" @click="searchCommentsVulnerable">
                Ejecutar POST vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureComments" @click="searchCommentsSecure">
                Ejecutar POST seguro
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Resultado vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="commentsVulnerableMessage" :type="commentsVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ commentsVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ commentsVulnerablePreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ commentsVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(commentsVulnerableResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Resultado seguro
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="commentsSecureMessage" :type="commentsSecureOk ? 'success' : 'error'" outlined dense>
                    {{ commentsSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ commentsSecurePreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ commentsSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(commentsSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>
    </template>

    <template #remediation>
      <div class="didactic-stack remediation-stack">
        <div>
          <div class="mini-title">Cómo evitarlo a nivel de código</div>
          <ul class="remediation-list">
            <li>Usa DTOs tipados y contratos cerrados para el body.</li>
            <li>No aceptes una query documental completa desde el cliente.</li>
            <li>Construye la query en el backend con criterios controlados.</li>
            <li>Rechaza operadores peligrosos como <code>$ne</code>, <code>$gt</code>, <code>$regex</code> o <code>$where</code>.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave para el alumno</div>
          <p class="mini-text mb-0">
            En SQL Injection el ataque intenta romper una sentencia textual. En NoSQL Injection el riesgo suele estar en
            dejar que el cliente defina operadores y estructura de la query documental.
          </p>
        </div>
      </div>
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
        text: 'REST'
      },
      loginVulnerableResult: null,
      loginSecureResult: null,
      commentsVulnerableResult: null,
      commentsSecureResult: null,
      loginVulnerableMessage: '',
      loginSecureMessage: '',
      commentsVulnerableMessage: '',
      commentsSecureMessage: '',
      loginVulnerableOk: false,
      loginSecureOk: false,
      commentsVulnerableOk: false,
      commentsSecureOk: false,
      loginVulnerableCode: [
        'public NoSqlLoginResponse loginVulnerable(Map<String, Object> body) {',
        '    List<NoSqlUserResponse> users = mongoTemplate',
        '        .find(buildVulnerableLoginQuery(body), Document.class, USERS_COLLECTION)',
        '        .stream()',
        '        .map(this::toUserResponse)',
        '        .toList();',
        '    return new NoSqlLoginResponse(!users.isEmpty(), users);',
        '}'
      ].join('\n'),
      loginSecureCode: [
        'public NoSqlLoginResponse loginSecure(NoSqlLoginRequest request) {',
        '    String username = requireSafeString(request.username(), "username");',
        '    String password = requireSafeString(request.password(), "password");',
        '    Query query = buildSecureLoginQuery(username, password);',
        '    return new NoSqlLoginResponse(!users.isEmpty(), users);',
        '}'
      ].join('\n'),
      commentsVulnerableCode: [
        'public List<NoSqlCommentResponse> searchCommentsVulnerable(Map<String, Object> body) {',
        '    return mongoTemplate',
        '        .find(buildVulnerableCommentQuery(body), Document.class, COMMENTS_COLLECTION)',
        '        .stream()',
        '        .map(this::toCommentResponse)',
        '        .toList();',
        '}'
      ].join('\n'),
      commentsSecureCode: [
        'public List<NoSqlCommentResponse> searchCommentsSecure(NoSqlCommentSearchRequest request) {',
        '    String text = requireSafeString(request.text(), "text");',
        '    Query query = buildSecureCommentQuery(text);',
        '    return mongoTemplate.find(query, Document.class, COMMENTS_COLLECTION).stream().map(this::toCommentResponse).toList();',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Login documental',
          text: 'Si el backend acepta un objeto JSON libre para username y password, operadores como $ne pueden cambiar la validación.'
        },
        {
          title: 'Búsquedas avanzadas',
          text: 'Filtros enviados como JSON pueden introducir $regex, $gt o $where y alterar la consulta.'
        },
        {
          title: 'APIs JSON flexibles',
          text: 'Cuanto más genérico es el contrato del body, más fácil es que el cliente controle la query.'
        },
        {
          title: 'Backends que delegan demasiado',
          text: 'El fallo aparece cuando el servidor acepta la estructura de consulta definida por el cliente.'
        }
      ],
      loginPayloads: [
        {
          label: '$ne / bypass',
          vulnerableJson: '{\n  "username": { "$ne": null },\n  "password": { "$ne": null }\n}',
          secureUsername: 'alice',
          securePassword: 'password123'
        },
        {
          label: 'alice legítimo',
          vulnerableJson: '{\n  "username": "alice",\n  "password": "password123"\n}',
          secureUsername: 'alice',
          securePassword: 'password123'
        }
      ],
      commentPayloads: [
        {
          label: '$regex amplio',
          vulnerableJson: '{\n  "text": { "$regex": ".*" }\n}',
          secureText: 'REST'
        },
        {
          label: '$ne null',
          vulnerableJson: '{\n  "visibility": { "$ne": null }\n}',
          secureText: 'MongoDB'
        }
      ],
      remediationPoints: [
        'Usar DTOs tipados y validación estricta.',
        'Rechazar operadores MongoDB como $ne, $gt, $regex o $where.',
        'Nunca pasar JSON arbitrario directamente a la query.'
      ],
      sideBullets: [
        'El riesgo aparece cuando la entrada se trata como parte de la consulta documental.',
        'La versión segura solo acepta campos esperados y construye la query en el servidor.'
      ]
    }
  },
  computed: {
    loginVulnerablePreview () {
      return [
        'Body recibido:',
        this.vulnerableLoginJson,
        '',
        'MongoDB interpreta ese body como filtro documental.'
      ].join('\n')
    },
    loginSecurePreview () {
      return [
        'Query construida por el backend:',
        '{ "username": "<valor exacto>", "password": "<valor exacto>" }',
        '',
        `username = ${this.secureLogin.username || '(cadena vacia)'}`,
        `password = ${this.secureLogin.password || '(cadena vacia)'}`
      ].join('\n')
    },
    commentsVulnerablePreview () {
      return [
        'Body recibido:',
        this.vulnerableCommentsJson,
        '',
        'MongoDB interpreta ese body como filtro documental.'
      ].join('\n')
    },
    commentsSecurePreview () {
      return [
        'Query construida por el backend:',
        '{ "text": /texto escapado/i, "visibility": "PUBLIC" }',
        '',
        `text = ${this.secureComments.text || '(cadena vacia)'}`,
        'visibility = PUBLIC'
      ].join('\n')
    },
    loginVulnerableExplanation () {
      if (this.vulnerableLoginJson.includes('$ne')) {
        return 'El operador $ne significa "distinto de". Si el backend acepta ese objeto como query, deja de comprobar credenciales exactas y puede autenticarse cualquier usuario que tenga campos no nulos.'
      }

      return 'El riesgo no está en el JSON en sí, sino en permitir que el cliente defina operadores y estructura de la query de login.'
    },
    loginSecureExplanation () {
      return 'El endpoint seguro no acepta un objeto documental arbitrario. Solo recibe username y password como strings y construye la query internamente con igualdad exacta.'
    },
    commentsVulnerableExplanation () {
      if (this.vulnerableCommentsJson.includes('$regex')) {
        return 'El operador $regex convierte la búsqueda en un patrón abierto. Un payload como .* puede ampliar el alcance del filtro y devolver comentarios fuera del caso previsto.'
      }

      if (this.vulnerableCommentsJson.includes('$ne')) {
        return 'El operador $ne permite construir un filtro que no responde al caso de uso original. El cliente está redefiniendo la consulta.'
      }

      return 'El body vulnerable se interpreta como query completa, así que el cliente puede cambiar el significado de la búsqueda.'
    },
    commentsSecureExplanation () {
      return 'La versión segura recibe solo un texto y monta una búsqueda controlada con regex escapada y visibility = PUBLIC. El cliente ya no controla operadores MongoDB.'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    parseJson (value) {
      return JSON.parse(value)
    },
    setLoginPayload(item) {
      this.vulnerableLoginJson = item.vulnerableJson
      this.secureLogin.username = item.secureUsername
      this.secureLogin.password = item.securePassword
    },
    setCommentPayload(item) {
      this.vulnerableCommentsJson = item.vulnerableJson
      this.secureComments.text = item.secureText
    },
    async loginVulnerable() {
      this.loading.vulnerableLogin = true
      try {
        const payload = this.parseJson(this.vulnerableLoginJson)
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/login`, payload)
        this.loginVulnerableResult = response.data
        this.loginVulnerableMessage = response.data && response.data.authenticated
          ? 'El POST vulnerable aceptó un body que redefinió la query documental del login.'
          : 'El POST vulnerable no autenticó en este intento, pero el backend sigue aceptando la estructura de query definida por el cliente.'
        this.loginVulnerableOk = !!(response.data && response.data.authenticated)
      } catch (error) {
        this.loginVulnerableResult = apiPayload(error)
        this.loginVulnerableMessage = apiMessage(error)
        this.loginVulnerableOk = false
      } finally {
        this.loading.vulnerableLogin = false
      }
    },
    async loginSecure() {
      this.loading.secureLogin = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/login-secure`, this.secureLogin)
        this.loginSecureResult = response.data
        this.loginSecureMessage = response.data && response.data.authenticated
          ? 'El POST seguro solo autenticó con credenciales exactas.'
          : 'El POST seguro trató los campos como strings y no aceptó operadores MongoDB.'
        this.loginSecureOk = !!(response.data && response.data.authenticated)
      } catch (error) {
        this.loginSecureResult = apiPayload(error)
        this.loginSecureMessage = apiMessage(error)
        this.loginSecureOk = false
      } finally {
        this.loading.secureLogin = false
      }
    },
    async searchCommentsVulnerable() {
      this.loading.vulnerableComments = true
      try {
        const payload = this.parseJson(this.vulnerableCommentsJson)
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/search-comments`, payload)
        this.commentsVulnerableResult = response.data
        this.commentsVulnerableMessage = 'La búsqueda vulnerable procesó el body completo como query MongoDB.'
        this.commentsVulnerableOk = true
      } catch (error) {
        this.commentsVulnerableResult = apiPayload(error)
        this.commentsVulnerableMessage = apiMessage(error)
        this.commentsVulnerableOk = false
      } finally {
        this.loading.vulnerableComments = false
      }
    },
    async searchCommentsSecure() {
      this.loading.secureComments = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/nosqli/search-comments-secure`, this.secureComments)
        this.commentsSecureResult = response.data
        this.commentsSecureMessage = 'La búsqueda segura construyó el filtro en backend y limitó los resultados a comentarios públicos.'
        this.commentsSecureOk = true
      } catch (error) {
        this.commentsSecureResult = apiPayload(error)
        this.commentsSecureMessage = apiMessage(error)
        this.commentsSecureOk = false
      } finally {
        this.loading.secureComments = false
      }
    }
  }
}
</script>

<style scoped>
.json-box,
.code-box,
.sql-box {
  background: #0f172a;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
}

.json-box {
  min-height: 140px;
}

.code-box,
.sql-box {
  min-height: 108px;
}

.sql-box--danger {
  border-left: 4px solid #c62828;
}

.sql-box--safe {
  border-left: 4px solid #2e7d32;
}

.didactic-stack > * + * {
  margin-top: 14px;
}

.didactic-stack {
  min-height: 560px;
  display: flex;
  flex-direction: column;
}

.remediation-stack {
  min-height: 0;
}

.mini-title,
.code-caption,
.flow-block__title {
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 8px;
}

.mini-text {
  color: #4b5563;
  margin: 0;
}

.compact-list {
  padding-left: 18px;
  margin-bottom: 0;
}

.context-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.context-item {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 14px;
  background: #fafafa;
}

.context-item__title {
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 6px;
}

.context-item__text {
  color: #4b5563;
  font-size: 0.95rem;
}

.payload-actions {
  display: flex;
  flex-wrap: wrap;
  margin-top: 8px;
}

.flow-block--spaced {
  margin-top: 20px;
}

.result-card {
  box-shadow: none !important;
}

.full-height {
  height: 100%;
}

.explanation-box {
  margin-top: 12px;
  padding: 12px 14px;
  border-radius: 8px;
  font-size: 0.95rem;
}

.explanation-box--danger {
  background: #fff5f5;
  border: 1px solid rgba(198, 40, 40, 0.18);
  color: #7f1d1d;
}

.explanation-box--safe {
  background: #f1fbf3;
  border: 1px solid rgba(46, 125, 50, 0.18);
  color: #166534;
}

.code-caption--danger {
  color: #b91c1c;
}

.code-caption--safe {
  color: #166534;
}

@media (max-width: 960px) {
  .context-grid {
    grid-template-columns: 1fr;
  }

  .didactic-stack {
    min-height: 0;
  }
}
</style>
