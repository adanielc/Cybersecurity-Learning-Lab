<template>
  <lab-page-shell
    title="SQL Injection"
    icon="mdi-database-search"
    description="Una SQL Injection aparece cuando el backend mezcla datos del usuario con la consulta SQL. Aquí se comparan dos escenarios: un GET de búsqueda y un POST de login con bypass."
    vulnerable-endpoint="GET /api/lab/sqli/users/search | POST /api/lab/sqli/login"
    secure-endpoint="GET /api/lab/sqli/users/search-secure | POST /api/lab/sqli/login-secure"
    vulnerable-method="GET / POST"
    secure-method="GET / POST"
    vulnerable-hint="La versión vulnerable concatena el valor recibido y lo convierte en parte del SQL."
    secure-hint="La versión segura separa la estructura SQL del dato usando parámetros."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="El verbo HTTP no provoca la vulnerabilidad. Un GET de búsqueda y un POST de login son vulnerables exactamente por el mismo motivo: el backend concatena entrada del usuario dentro de la sentencia SQL."
    owasp-label="OWASP A03: Injection"
    risk-label="Impacto alto: fuga de datos, bypass de login y manipulación del WHERE"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué pasa por detrás</div>
          <p class="mini-text">
            En el flujo vulnerable el backend arma un string SQL final. Da igual si el dato viene de un
            <code>query param</code> en un GET o de un <code>JSON body</code> en un POST.
          </p>
        </div>

        <div>
          <div class="mini-title">GET vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ searchVulnerableQueryPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">POST vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ loginVulnerableQueryPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>En búsqueda puede ampliar o alterar el filtro.</li>
            <li>En login puede anular la comprobación del password y hacer bypass.</li>
            <li>La base de datos ejecuta la consulta alterada porque el payload pasó a ser código SQL.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué cambia</div>
          <p class="mini-text">
            En el flujo seguro el SQL queda fijo y los valores se envían como parámetros. El payload llega a la base
            de datos como dato literal, no como una nueva condición del <code>WHERE</code>.
          </p>
        </div>

        <div>
          <div class="mini-title">GET seguro</div>
          <pre class="sql-box sql-box--safe">{{ searchSecureQueryPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">POST seguro</div>
          <pre class="sql-box sql-box--safe">{{ loginSecureQueryPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>La búsqueda sigue comparando solo el campo esperado.</li>
            <li>El login sigue comprobando username y password reales.</li>
            <li>El payload no puede cerrar comillas ni comentar el resto de la sentencia.</li>
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
            <div class="flow-block__title">Escenario 1: GET de búsqueda</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ searchVulnerableCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ searchSecureCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: POST de login</div>
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
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: GET de búsqueda
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            En este caso el usuario manipula el parámetro <code>username</code> de una búsqueda. La inyección cambia
            el filtro del <code>WHERE</code> y puede devolver más filas de las previstas.
          </p>

          <v-row>
            <v-col cols="12">
              <v-text-field
                v-model="searchUsername"
                label="Valor enviado en username"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="item in searchPayloads"
              :key="item.value"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="setSearchPayload(item.value)"
            >
              {{ item.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loadingSearchVulnerable" @click="searchVulnerable">
                Ejecutar GET vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loadingSearchSecure" @click="searchSecure">
                Ejecutar GET seguro
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
                  <v-alert v-if="searchVulnerableMessage" :type="searchVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ searchVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ searchVulnerableQueryPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ searchVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(searchVulnerableResult) }}</pre>
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
                  <v-alert v-if="searchSecureMessage" :type="searchSecureOk ? 'success' : 'error'" outlined dense>
                    {{ searchSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ searchSecureQueryPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ searchSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(searchSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: POST de login con bypass
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aquí el atacante no quiere ampliar una búsqueda, sino entrar sin credenciales válidas. El objetivo es romper
            la condición <code>username = ... AND password = ...</code> para que el backend dé por autenticado al usuario.
          </p>

          <v-row>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="loginForm.username"
                label="Username enviado en el POST"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="loginForm.password"
                label="Password enviado en el POST"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

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

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loadingLoginVulnerable" @click="loginVulnerable">
                Ejecutar POST vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loadingLoginSecure" @click="loginSecure">
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

                  <pre class="sql-box sql-box--danger">{{ loginVulnerableQueryPreview }}</pre>
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

                  <pre class="sql-box sql-box--safe">{{ loginSecureQueryPreview }}</pre>
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
    </template>

    <template #remediation>
      <div class="didactic-stack remediation-stack">
        <div>
          <div class="mini-title">Cómo evitarlo a nivel de código</div>
          <ul class="remediation-list">
            <li>Usa consultas parametrizadas, prepared statements, JPA o query builders seguros.</li>
            <li>No concatenes datos de entrada en <code>WHERE</code>, <code>ORDER BY</code> ni cláusulas dinámicas.</li>
            <li>Valida la entrada, pero no la uses como sustituto de parametrizar.</li>
            <li>Aplica mínimo privilegio en la cuenta de base de datos para reducir el impacto si algo falla.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave</div>
          <p class="mini-text mb-0">
            La diferencia entre GET y POST aquí no es de seguridad. El riesgo aparece cuando el backend convierte la
            entrada del usuario en parte de la sentencia SQL, ya sea en una búsqueda o en un login.
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
      searchUsername: 'alice',
      loginForm: {
        username: 'alice',
        password: 'password123'
      },
      loadingSearchVulnerable: false,
      loadingSearchSecure: false,
      loadingLoginVulnerable: false,
      loadingLoginSecure: false,
      searchVulnerableResult: null,
      searchSecureResult: null,
      loginVulnerableResult: null,
      loginSecureResult: null,
      searchVulnerableMessage: '',
      searchSecureMessage: '',
      loginVulnerableMessage: '',
      loginSecureMessage: '',
      searchVulnerableOk: false,
      searchSecureOk: false,
      loginVulnerableOk: false,
      loginSecureOk: false,
      searchVulnerableCode: [
        'public List<SqlInjectionUserResponse> searchVulnerable(String username) {',
        '    String sql = "SELECT id, username, email, role FROM lab_users WHERE username = \'" + username + "\'";',
        '    return jdbcTemplate.query(sql, rowMapper);',
        '}'
      ].join('\n'),
      searchSecureCode: [
        'public List<SqlInjectionUserResponse> searchSecure(String username) {',
        '    String sql = "SELECT id, username, email, role FROM lab_users WHERE username = ?";',
        '    return jdbcTemplate.query(sql, rowMapper, username);',
        '}'
      ].join('\n'),
      loginVulnerableCode: [
        'public SqlInjectionLoginResponse loginVulnerable(LoginRequest request) {',
        '    String sql = "SELECT id, username, email, role FROM lab_users WHERE username = \'"',
        '        + request.username() + "\' AND password = \'" + request.password() + "\'";',
        '    List<SqlInjectionUserResponse> users = jdbcTemplate.query(sql, rowMapper);',
        '    return new SqlInjectionLoginResponse(!users.isEmpty(), users.size(), users);',
        '}'
      ].join('\n'),
      loginSecureCode: [
        'public SqlInjectionLoginResponse loginSecure(LoginRequest request) {',
        '    String sql = "SELECT id, username, email, role FROM lab_users WHERE username = ? AND password = ?";',
        '    List<SqlInjectionUserResponse> users = jdbcTemplate.query(sql, rowMapper, request.username(), request.password());',
        '    return new SqlInjectionLoginResponse(!users.isEmpty(), users.size(), users);',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Búsquedas y filtros GET',
          text: 'Un parámetro como username, email o id acaba dentro de un WHERE y altera el filtro.'
        },
        {
          title: 'Login POST',
          text: 'Username y password también pueden inyectarse si el backend concatena ambos en la misma consulta.'
        },
        {
          title: 'Paneles y listados',
          text: 'Filtros, ordenaciones, exportaciones y búsquedas avanzadas son puntos clásicos de SQL dinámico inseguro.'
        },
        {
          title: 'APIs JSON',
          text: 'No importa si el dato llega por query string o por body. El fallo está en cómo se construye el SQL.'
        }
      ],
      searchPayloads: [
        { label: 'alice', value: 'alice' },
        { label: "' OR '1'='1", value: "' OR '1'='1" },
        { label: "admin' --", value: "admin' --" }
      ],
      loginPayloads: [
        { label: 'alice / password123', username: 'alice', password: 'password123' },
        { label: "admin' -- / noimporta", username: "admin' --", password: 'noimporta' },
        { label: "' OR '1'='1' -- / noimporta", username: "' OR '1'='1' --", password: 'noimporta' }
      ],
      remediationPoints: [
        'Usar consultas parametrizadas o JPA seguro.',
        'Separar de forma estricta SQL y datos de entrada.',
        'Reducir privilegios de la cuenta de base de datos.'
      ],
      sideBullets: [
        'La vulnerabilidad nace en el backend cuando se concatena la entrada dentro del SQL.',
        'En un GET suele alterar el filtro; en un POST de login puede producir bypass de autenticación.'
      ]
    }
  },
  computed: {
    searchVulnerableQueryPreview () {
      return `SELECT id, username, email, role FROM lab_users WHERE username = '${this.searchUsername}'`
    },
    searchSecureQueryPreview () {
      return [
        'SQL: SELECT id, username, email, role FROM lab_users WHERE username = ?',
        `Parametro 1: ${this.searchUsername === '' ? '(cadena vacia)' : this.searchUsername}`
      ].join('\n')
    },
    loginVulnerableQueryPreview () {
      return `SELECT id, username, email, role FROM lab_users WHERE username = '${this.loginForm.username}' AND password = '${this.loginForm.password}'`
    },
    loginSecureQueryPreview () {
      return [
        'SQL: SELECT id, username, email, role FROM lab_users WHERE username = ? AND password = ?',
        `Parametro 1: ${this.loginForm.username === '' ? '(cadena vacia)' : this.loginForm.username}`,
        `Parametro 2: ${this.loginForm.password === '' ? '(cadena vacia)' : this.loginForm.password}`
      ].join('\n')
    },
    searchVulnerableExplanation () {
      const value = this.searchUsername

      if (value === "' OR '1'='1") {
        return 'El payload cierra la comilla original y añade una condición siempre verdadera. El WHERE deja de buscar un usuario concreto y puede devolver múltiples filas.'
      }

      if (value === "admin' --") {
        return 'El payload intenta cerrar la cadena y comentar el resto. Aunque aquí el caso más típico es el bypass de login, sigue siendo una manipulación del SQL original.'
      }

      if (!value) {
        return 'Con una cadena vacía no hay bypass, pero el defecto sigue siendo el mismo: la consulta se arma concatenando texto del usuario.'
      }

      return 'Con un valor normal parece una búsqueda legítima, pero la consulta sigue siendo vulnerable porque el usuario controla una parte del SQL final.'
    },
    searchSecureExplanation () {
      const value = this.searchUsername || '(cadena vacia)'
      return `El placeholder ? mantiene fijo el WHERE. El valor "${value}" viaja como dato y no puede alterar la lógica de la consulta.`
    },
    loginVulnerableExplanation () {
      const username = this.loginForm.username

      if (username === "admin' --") {
        return 'El payload cierra la cadena de username y comenta el resto de la consulta. La comprobación del password puede quedar anulada y el backend aceptar el login sin conocer la contraseña real.'
      }

      if (username === "' OR '1'='1' --") {
        return 'El payload introduce una condición siempre verdadera y después comenta el resto del WHERE. Eso puede convertir el login en un bypass si la consulta devuelve alguna fila.'
      }

      return 'Cuando username y password se concatenan dentro del SQL, el login deja de ser una validación de credenciales y pasa a ser una cadena manipulable por el atacante.'
    },
    loginSecureExplanation () {
      return 'En la versión segura, username y password se envían como parámetros separados. Aunque uno de los campos contenga comillas, operadores o comentarios, la base de datos los trata como texto literal.'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    setSearchPayload (value) {
      this.searchUsername = value
    },
    setLoginPayload (payload) {
      this.loginForm.username = payload.username
      this.loginForm.password = payload.password
    },
    async searchVulnerable () {
      this.loadingSearchVulnerable = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/sqli/users/search`, {
          params: { username: this.searchUsername }
        })
        this.searchVulnerableResult = response.data
        this.searchVulnerableMessage = 'El GET vulnerable ejecutó la consulta concatenando el valor del query param dentro del WHERE.'
        this.searchVulnerableOk = true
      } catch (error) {
        this.searchVulnerableResult = apiPayload(error)
        this.searchVulnerableMessage = apiMessage(error)
        this.searchVulnerableOk = false
      } finally {
        this.loadingSearchVulnerable = false
      }
    },
    async searchSecure () {
      this.loadingSearchSecure = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/sqli/users/search-secure`, {
          params: { username: this.searchUsername }
        })
        this.searchSecureResult = response.data
        this.searchSecureMessage = 'El GET seguro mantuvo la consulta fija y envió username como parámetro.'
        this.searchSecureOk = true
      } catch (error) {
        this.searchSecureResult = apiPayload(error)
        this.searchSecureMessage = apiMessage(error)
        this.searchSecureOk = false
      } finally {
        this.loadingSearchSecure = false
      }
    },
    async loginVulnerable () {
      this.loadingLoginVulnerable = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/sqli/login`, this.loginForm)
        this.loginVulnerableResult = response.data
        this.loginVulnerableMessage = response.data && response.data.authenticated
          ? 'El POST vulnerable devolvió filas y el login queda bypassed o autenticado por una consulta alterada.'
          : 'El POST vulnerable no autenticó en este intento, pero la consulta sigue siendo manipulable.'
        this.loginVulnerableOk = !!(response.data && response.data.authenticated)
      } catch (error) {
        this.loginVulnerableResult = apiPayload(error)
        this.loginVulnerableMessage = apiMessage(error)
        this.loginVulnerableOk = false
      } finally {
        this.loadingLoginVulnerable = false
      }
    },
    async loginSecure () {
      this.loadingLoginSecure = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/sqli/login-secure`, this.loginForm)
        this.loginSecureResult = response.data
        this.loginSecureMessage = response.data && response.data.authenticated
          ? 'El POST seguro solo autenticó cuando username y password coinciden de verdad.'
          : 'El POST seguro trató el payload como dato y no permitió el bypass.'
        this.loginSecureOk = !!(response.data && response.data.authenticated)
      } catch (error) {
        this.loginSecureResult = apiPayload(error)
        this.loginSecureMessage = apiMessage(error)
        this.loginSecureOk = false
      } finally {
        this.loadingLoginSecure = false
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
