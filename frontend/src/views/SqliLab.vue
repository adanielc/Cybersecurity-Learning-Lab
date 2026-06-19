<template>
  <lab-page-shell
    title="SQL Injection"
    icon="mdi-database-search"
    description="Una SQL Injection aparece cuando el backend mezcla datos del usuario con la consulta SQL. El laboratorio compara una búsqueda vulnerable con una consulta parametrizada segura."
    vulnerable-endpoint="GET /api/lab/sqli/users/search?username=valor"
    secure-endpoint="GET /api/lab/sqli/users/search-secure?username=valor"
    vulnerable-hint="La consulta vulnerable concatena el parámetro y convierte la entrada en parte del SQL."
    secure-hint="La consulta segura separa la estructura SQL del dato usando parámetros."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="SQL Injection no solo aparece en búsquedas. También es común en formularios de login, filtros, pantallas de administración, exportaciones y cualquier endpoint que construya SQL dinámico sin parametrizar."
    owasp-label="OWASP A03: Injection"
    risk-label="Impacto alto: fuga de datos, bypass de login y manipulación de consultas"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué pasa por detrás</div>
          <p class="mini-text">
            El backend recibe el valor de <code>username</code> y lo pega dentro del <code>WHERE</code>.
            Si el usuario escribe un payload como <code>' OR '1'='1</code>, la condición deja de ser una búsqueda exacta.
          </p>
        </div>

        <div>
          <div class="mini-title">Consulta construida</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableQueryPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Fallo real</div>
          <ul class="remediation-list compact-list">
            <li>La entrada del usuario se mezcla con el código SQL.</li>
            <li>La base de datos interpreta el payload como lógica, no como texto.</li>
            <li>Esto puede devolver más filas de las esperadas o alterar la consulta.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué cambia</div>
          <p class="mini-text">
            El SQL mantiene un placeholder <code>?</code> y el valor viaja aparte. Aunque el usuario envíe un payload,
            la base de datos lo trata como dato literal.
          </p>
        </div>

        <div>
          <div class="mini-title">Consulta segura</div>
          <pre class="sql-box sql-box--safe">{{ secureQueryPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>La consulta no cambia de significado.</li>
            <li>El payload no puede abrir comillas ni inyectar operadores.</li>
            <li>La búsqueda sigue siendo exacta para el campo esperado.</li>
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
          <v-row>
            <v-col cols="12" md="6">
              <div class="code-caption code-caption--danger">Versión vulnerable</div>
              <pre class="code-box">{{ vulnerableCode }}</pre>
            </v-col>
            <v-col cols="12" md="6">
              <div class="code-caption code-caption--safe">Versión segura</div>
              <pre class="code-box">{{ secureCode }}</pre>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Prueba el payload
        </v-card-title>
        <v-divider />
        <v-card-text>
          <v-row>
            <v-col cols="12">
              <v-text-field
                v-model="username"
                label="Valor enviado en username"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="item in quickPayloads"
              :key="item.value"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="setPayload(item.value)"
            >
              {{ item.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loadingVulnerable" @click="searchVulnerable">
                Ejecutar búsqueda vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loadingSecure" @click="searchSecure">
                Ejecutar búsqueda segura
              </v-btn>
            </v-col>
          </v-row>

          <v-alert type="info" outlined dense class="mt-4 mb-0">
            En un formulario de login ocurre lo mismo si alguien construye algo como
            <code>SELECT * FROM users WHERE username = '...'</code> y concatena también el password.
            El problema no es el tipo de pantalla, sino concatenar entrada de usuario dentro del SQL.
          </v-alert>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Resultado vulnerable
        </v-card-title>
        <v-divider />
        <v-card-text>
          <v-alert v-if="vulnerableMessage" :type="vulnerableOk ? 'success' : 'error'" outlined dense>
            {{ vulnerableMessage }}
          </v-alert>

          <v-card outlined class="mb-4 result-card">
            <v-card-title class="subtitle-2">
              Qué ha interpretado la base de datos
            </v-card-title>
            <v-divider />
            <v-card-text>
              <pre class="sql-box sql-box--danger">{{ vulnerableQueryPreview }}</pre>
              <div class="explanation-box explanation-box--danger">
                {{ vulnerableExplanation }}
              </div>
            </v-card-text>
          </v-card>

          <pre class="json-box">{{ pretty(vulnerableResult) }}</pre>
        </v-card-text>
      </v-card>

      <v-card outlined>
        <v-card-title class="subtitle-2">
          Resultado seguro
        </v-card-title>
        <v-divider />
        <v-card-text>
          <v-alert v-if="secureMessage" :type="secureOk ? 'success' : 'error'" outlined dense>
            {{ secureMessage }}
          </v-alert>

          <v-card outlined class="mb-4 result-card">
            <v-card-title class="subtitle-2">
              Cómo se protege la consulta
            </v-card-title>
            <v-divider />
            <v-card-text>
              <pre class="sql-box sql-box--safe">{{ secureQueryPreview }}</pre>
              <div class="explanation-box explanation-box--safe">
                {{ secureExplanation }}
              </div>
            </v-card-text>
          </v-card>

          <pre class="json-box">{{ pretty(secureResult) }}</pre>
        </v-card-text>
      </v-card>
    </template>

    <template #remediation>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Cómo evitarlo a nivel de código</div>
          <ul class="remediation-list">
            <li>Usa consultas parametrizadas, prepared statements, JPA o query builders seguros.</li>
            <li>No construyas <code>WHERE</code>, <code>ORDER BY</code> ni fragmentos SQL con concatenación de strings.</li>
            <li>Valida la entrada, pero no confíes en la validación como sustituto de la parametrización.</li>
            <li>Aplica mínimo privilegio en la cuenta de base de datos para reducir impacto si algo falla.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave para el alumno</div>
          <p class="mini-text mb-0">
            SQL Injection no depende de que el campo sea de búsqueda o de login. Aparece cuando el backend trata
            la entrada del usuario como parte del comando SQL en vez de tratarla como dato.
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
      vulnerableCode: [
        'public List<SqlInjectionUserResponse> searchVulnerable(String username) {',
        '    String sql = "SELECT id, username, email, role FROM lab_users WHERE username = \'" + username + "\'";',
        '    return jdbcTemplate.query(sql, rowMapper);',
        '}'
      ].join('\n'),
      secureCode: [
        'public List<SqlInjectionUserResponse> searchSecure(String username) {',
        '    String sql = "SELECT id, username, email, role FROM lab_users WHERE username = ?";',
        '    return jdbcTemplate.query(sql, rowMapper, username);',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Búsquedas y filtros',
          text: 'Campos como username, email, id, fecha o texto libre suelen terminar dentro de un WHERE.'
        },
        {
          title: 'Formularios de login',
          text: 'También puede aparecer si username y password se concatenan para validar credenciales.'
        },
        {
          title: 'Paneles de administración',
          text: 'Listados con filtros, ordenaciones o exportaciones son un punto clásico cuando se construye SQL dinámico.'
        },
        {
          title: 'APIs con parámetros',
          text: 'No importa si viene de un form, query param o JSON: el problema es cómo se arma la consulta.'
        }
      ],
      quickPayloads: [
        { label: 'alice', value: 'alice' },
        { label: "' OR '1'='1", value: "' OR '1'='1" },
        { label: "admin' --", value: "admin' --" }
      ],
      remediationPoints: [
        'Usar consultas parametrizadas o JPA seguro.',
        'Separar claramente SQL y datos de usuario.',
        'Reducir privilegios de la cuenta de base de datos.'
      ],
      sideBullets: [
        'La vulnerabilidad nace en el backend cuando se concatena la entrada dentro del SQL.',
        'Un payload puede cambiar la lógica del WHERE y devolver filas no previstas.'
      ]
    }
  },
  computed: {
    vulnerableQueryPreview () {
      return `SELECT id, username, email, role FROM lab_users WHERE username = '${this.username}'`
    },
    secureQueryPreview () {
      return [
        'SQL: SELECT id, username, email, role FROM lab_users WHERE username = ?',
        `Parametro 1: ${this.username === '' ? '(cadena vacia)' : this.username}`
      ].join('\n')
    },
    vulnerableExplanation () {
      const value = this.username

      if (value === "' OR '1'='1") {
        return 'El payload cierra la comilla original y añade una condición siempre verdadera. La búsqueda puede devolver múltiples usuarios porque el WHERE deja de comparar solo el username.'
      }

      if (value === "admin' --") {
        return 'El payload intenta cerrar la cadena y comentar el resto de la consulta. En muchos escenarios esto altera el SQL original o elimina parte de la condición esperada.'
      }

      if (!value) {
        return 'Aunque el valor esté vacío, el problema sigue siendo el mismo: la consulta se construye concatenando texto, y eso deja la puerta abierta a payloads más peligrosos.'
      }

      return 'Con un valor normal la consulta parece funcionar, pero el defecto sigue ahí. El problema no se ve siempre a simple vista; aparece cuando un atacante envía un payload que modifica el SQL.'
    },
    secureExplanation () {
      const value = this.username || '(cadena vacia)'
      return `El placeholder ? mantiene fija la estructura de la consulta. El valor "${value}" se envía como dato y no puede abrir comillas ni inyectar operadores SQL.`
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    setPayload (value) {
      this.username = value
    },
    async searchVulnerable () {
      this.loadingVulnerable = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/sqli/users/search`, {
          params: { username: this.username }
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'La búsqueda vulnerable ejecutó la consulta concatenada con el valor del usuario dentro del SQL.'
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
        this.secureMessage = 'La búsqueda segura mantuvo el SQL fijo y envió el valor del usuario como parámetro.'
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
  min-height: 120px;
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
  min-height: 520px;
}

.mini-title,
.code-caption {
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

.result-card {
  box-shadow: none !important;
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
}
</style>
