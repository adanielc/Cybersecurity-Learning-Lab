<template>
  <lab-page-shell
    title="Almacenamiento de tokens"
    icon="mdi-shield-key"
    description="El problema no es solo emitir un JWT, sino decidir donde vive en el navegador. Aqui se compara guardarlo en localStorage frente a mantenerlo en memoria o entregarlo en cookie HttpOnly."
    vulnerable-endpoint="POST /api/lab/token-storage/login"
    secure-endpoint="POST /api/lab/token-storage/login | GET /api/lab/token-storage/me"
    vulnerable-method="POST"
    secure-method="POST / GET"
    vulnerable-hint="La version vulnerable deja el token persistido en localStorage, donde cualquier XSS de la pagina puede leerlo."
    secure-hint="La version segura evita persistirlo en localStorage; la opcion mas robusta frente a lectura desde JavaScript es cookie HttpOnly."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="Token storage es una decision de superficie de ataque. Un XSS no necesita romper el backend si el navegador ya expone el token a JavaScript o lo deja persistido mas tiempo del necesario."
    owasp-label="OWASP A07:2021 Identification and Authentication Failures"
    risk-label="Impacto alto: robo de token y reutilizacion de sesion"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que pasa por detras</div>
          <p class="mini-text">
            El backend emite un JWT y la SPA lo guarda en <code>localStorage</code>. Eso hace que el token sobreviva a
            recargas y quede accesible desde cualquier JavaScript que llegue a ejecutarse en esa misma pagina.
          </p>
        </div>

        <div>
          <div class="mini-title">Flujo vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Lo que puede hacer un XSS</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>El token queda persistido incluso tras recargar la pestana.</li>
            <li>Un script inyectado puede leerlo con <code>localStorage.getItem(...)</code>.</li>
            <li>El robo del token permite reutilizar la sesion mientras siga vigente.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que cambia</div>
          <p class="mini-text">
            La version segura evita dejar el token en <code>localStorage</code>. Si se mantiene en memoria, reduce
            persistencia pero sigue siendo visible para un XSS en la misma pagina. Si se entrega en
            <code>cookie HttpOnly</code>, JavaScript ya no puede leerlo directamente.
          </p>
        </div>

        <div>
          <div class="mini-title">Flujo seguro</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Lectura desde JavaScript</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>Modo memoria: el token desaparece al recargar, pero sigue siendo visible al mismo JavaScript de la pagina.</li>
            <li>Modo cookie HttpOnly: el navegador envia la cookie, pero JavaScript no puede inspeccionarla.</li>
            <li>La opcion recomendada frente a robo por XSS es minimizar superficie y preferir HttpOnly si encaja con el caso.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #form>
      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Donde suele aparecer
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
          Codigo del backend y del cliente
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: emision del token</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: uso posterior del token</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption">Lectura local</div>
                <pre class="code-box">{{ localReadCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption">Acceso a /me</div>
                <pre class="code-box">{{ meCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: login y decision de almacenamiento
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aqui se emite el token y la diferencia empieza en el cliente. La version vulnerable siempre lo persiste en
            <code>localStorage</code>. La segura permite compararlo con memoria o con <code>cookie HttpOnly</code>.
          </p>

          <v-row>
            <v-col cols="12" md="4">
              <v-text-field
                v-model="form.username"
                label="Username"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="4">
              <v-text-field
                v-model="form.password"
                label="Password"
                type="password"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="4">
              <v-select
                v-model="secureMode"
                :items="secureModes"
                label="Modo seguro"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="preset in presets"
              :key="preset.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="applyPreset(preset)"
            >
              {{ preset.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableLogin" @click="loginVulnerable">
                Ejecutar login vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureLogin" @click="loginSecure">
                Ejecutar login seguro
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
                  <v-alert v-if="vulnerableMessage" :type="vulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ vulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ vulnerableRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ vulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(vulnerableResult) }}</pre>
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
                  <v-alert v-if="secureMessage" :type="secureOk ? 'success' : 'error'" outlined dense>
                    {{ secureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ secureRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ secureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(secureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: que puede leer JavaScript y que valida el backend
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            En este escenario se simula lo que haria un JavaScript normal de la pagina o un XSS. Luego se compara con
            el acceso real al endpoint <code>/me</code>, que puede funcionar con cabecera o con cookie segun el modo.
          </p>

          <div class="payload-actions mb-2">
            <v-btn small outlined color="secondary" @click="readLocalStorageToken">
              Leer localStorage
            </v-btn>
            <v-btn small outlined color="secondary" @click="readMemoryToken">
              Leer memoria
            </v-btn>
            <v-btn small outlined color="secondary" @click="clearSession">
              Limpiar estado local
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.me" @click="loadCurrentUser">
                Consultar /me con el modo actual
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Lo que ve JavaScript
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="readMessage" type="info" outlined dense>
                    {{ readMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ readableStatePreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ readableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(readState) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Respuesta de /me
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="meMessage" :type="meOk ? 'success' : 'error'" outlined dense>
                    {{ meMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ meRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ meExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(meResponse) }}</pre>
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
          <div class="mini-title">Como evitarlo a nivel de codigo y cliente</div>
          <ul class="remediation-list">
            <li>Evita persistir access tokens en <code>localStorage</code> salvo necesidad muy justificada.</li>
            <li>Si el caso lo permite, prefiere <code>cookie HttpOnly</code> con <code>SameSite</code> y <code>Secure</code>.</li>
            <li>Si usas memoria, recuerda que sigue siendo visible al JavaScript de la pagina.</li>
            <li>Combina esta decision con protecciones XSS y expiraciones cortas.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave para el alumno</div>
          <p class="mini-text mb-0">
            El token puede ser valido criptograficamente y aun asi quedar demasiado expuesto por como se almacena en el
            navegador. Aqui el fallo es de superficie de robo, no de firma JWT.
          </p>
        </div>
      </div>
    </template>
  </lab-page-shell>
</template>

<script>
import LabPageShell from '../components/LabPageShell.vue'
import { DEFAULT_API_BASE_URL, apiMessage, apiPayload, prettyJson } from '../utils/labApi'

const TOKEN_KEY = 'tfm_lab_jwt'

export default {
  name: 'TokenStorageLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      form: {
        username: 'alice',
        password: 'password123'
      },
      secureMode: 'cookie',
      secureModes: [
        { text: 'cookie HttpOnly', value: 'cookie' },
        { text: 'memoria', value: 'memory' }
      ],
      loading: {
        vulnerableLogin: false,
        secureLogin: false,
        me: false
      },
      memoryToken: '',
      localStorageToken: window.localStorage.getItem(TOKEN_KEY) || '',
      vulnerableResult: null,
      secureResult: null,
      meResponse: null,
      readState: null,
      vulnerableMessage: '',
      secureMessage: '',
      meMessage: '',
      readMessage: '',
      vulnerableOk: false,
      secureOk: false,
      meOk: false,
      activeMode: 'none',
      presets: [
        { label: 'alice cookie', username: 'alice', password: 'password123', secureMode: 'cookie' },
        { label: 'alice memoria', username: 'alice', password: 'password123', secureMode: 'memory' },
        { label: 'admin cookie', username: 'admin', password: 'adminpass', secureMode: 'cookie' }
      ],
      vulnerableCode: [
        'const response = await api.post("/lab/token-storage/login", {',
        '  username,',
        '  password,',
        '  deliveryMode: "header"',
        '});',
        'window.localStorage.setItem("tfm_lab_jwt", response.data.accessToken);'
      ].join('\n'),
      secureCode: [
        'const response = await api.post("/lab/token-storage/login", {',
        '  username,',
        '  password,',
        '  deliveryMode: secureMode === "cookie" ? "cookie" : "header"',
        '}, { withCredentials: secureMode === "cookie" });',
        'memoryToken = secureMode === "memory" ? response.data.accessToken : "";'
      ].join('\n'),
      localReadCode: [
        'const local = window.localStorage.getItem("tfm_lab_jwt");',
        'const memory = this.memoryToken;',
        '// HttpOnly cookie no se puede leer desde JavaScript'
      ].join('\n'),
      meCode: [
        'const headers = token ? { Authorization: `Bearer ${token}` } : {};',
        'await api.get("/lab/token-storage/me", {',
        '  headers,',
        '  withCredentials: activeMode === "secure-cookie"',
        '});'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'SPAs con JWT',
          text: 'Una SPA puede recibir el token de forma correcta y aun asi exponerse demasiado si lo deja persistido donde cualquier script lo lea.'
        },
        {
          title: 'Aplicaciones con riesgo XSS',
          text: 'Si existe una inyeccion en la misma pagina, el almacenamiento decide si el token se puede extraer facilmente.'
        },
        {
          title: 'Sesiones largas en navegador',
          text: 'Cuanto mas dura y mas persiste el token, mayor es la ventana para robo o reutilizacion de sesion.'
        },
        {
          title: 'Arquitecturas SPA + API',
          text: 'El cliente suele decidir donde guarda el token, y esa decision cambia mucho la superficie de ataque sin tocar la firma JWT.'
        }
      ],
      remediationPoints: [
        'Evitar localStorage para access tokens salvo necesidad muy justificada.',
        'Preferir cookie HttpOnly si encaja con el flujo.',
        'Si usas memoria, asumir que un XSS de la pagina aun podria leerla.',
        'Mantener expiraciones cortas y buena postura XSS.'
      ],
      sideBullets: [
        'localStorage aumenta persistencia y facilita lectura por JavaScript.',
        'cookie HttpOnly reduce lectura desde JS, pero no sustituye una buena defensa XSS y CSRF segun el caso.'
      ]
    }
  },
  computed: {
    vulnerablePreview () {
      return [
        'JWT emitido en la respuesta',
        'Cliente lo copia a localStorage',
        'Persistencia = alta',
        'Lectura desde JavaScript = directa'
      ].join('\n')
    },
    securePreview () {
      return this.secureMode === 'cookie'
        ? [
            'JWT emitido como cookie HttpOnly',
            'Persistencia = controlada por cookie',
            'Lectura desde JavaScript = no',
            'Uso posterior = navegador envia la cookie con withCredentials'
          ].join('\n')
        : [
            'JWT emitido en cabecera/cuerpo',
            'Cliente lo mantiene solo en memoria',
            'Persistencia = baja (se pierde al recargar)',
            'Lectura desde JavaScript = si, mientras viva la pagina'
          ].join('\n')
    },
    vulnerableDecisionPreview () {
      return [
        'localStorage.getItem("tfm_lab_jwt") = available',
        'reload tab = token survives',
        'XSS same page = can exfiltrate token',
        'result = session theft becomes much easier'
      ].join('\n')
    },
    secureDecisionPreview () {
      return this.secureMode === 'cookie'
        ? [
            'document.cookie = HttpOnly token not visible',
            'same-page JavaScript = cannot read token value',
            'browser request = cookie can still be sent to backend',
            'result = lower token theft surface from XSS read access'
          ].join('\n')
        : [
            'memory variable = available only while tab lives',
            'same-page JavaScript = can still read it',
            'reload tab = token disappears',
            'result = less persistence, but not full protection against XSS'
          ].join('\n')
    },
    vulnerableRequestPreview () {
      return [
        'POST /api/lab/token-storage/login',
        '',
        `{ "username": "${this.form.username || '(vacio)'}", "password": "***", "deliveryMode": "header" }`,
        'Cliente: guarda accessToken en localStorage'
      ].join('\n')
    },
    secureRequestPreview () {
      return [
        'POST /api/lab/token-storage/login',
        '',
        `{ "username": "${this.form.username || '(vacio)'}", "password": "***", "deliveryMode": "${this.secureMode === 'cookie' ? 'cookie' : 'header'}" }`,
        this.secureMode === 'cookie' ? 'Cliente: withCredentials = true y sin acceso JS al valor' : 'Cliente: guarda accessToken solo en memoria'
      ].join('\n')
    },
    vulnerableExplanation () {
      return 'El token vulnerable queda persistido en localStorage. Eso no rompe la validacion del backend, pero facilita mucho su robo desde cualquier JavaScript que se ejecute en la pagina.'
    },
    secureExplanation () {
      return this.secureMode === 'cookie'
        ? 'En modo cookie, el backend sigue autenticando con el mismo JWT, pero JavaScript no recibe el valor legible. Ese es el contraste didactico importante frente a localStorage.'
        : 'En modo memoria, el token ya no persiste en localStorage y desaparece al recargar. Aun asi, si hubiese XSS en la misma pagina, ese script podria leer la variable mientras exista.'
    },
    readableStatePreview () {
      return [
        `localStorage token = ${this.localStorageToken ? 'visible' : 'vacio'}`,
        `memory token = ${this.memoryToken ? 'visible' : 'vacio'}`,
        `secure mode = ${this.secureMode}`,
        this.activeMode === 'secure-cookie' ? 'HttpOnly cookie = enviada por navegador, no legible por JavaScript' : 'Cookie HttpOnly = no activa en este flujo'
      ].join('\n')
    },
    readableExplanation () {
      if (this.activeMode === 'secure-cookie') {
        return 'El punto clave es que JavaScript puede seguir leyendo localStorage o memoria si existen, pero no puede inspeccionar una cookie HttpOnly. Por eso la lectura local del token falla en ese modo.'
      }

      if (this.memoryToken) {
        return 'Aqui se ve el matiz importante: memoria es mejor que localStorage en persistencia, pero no es invisible al mismo JavaScript de la pagina.'
      }

      return 'Si el token esta en localStorage, leerlo es trivial. Si no hay token local accesible, un XSS no puede extraerlo por esa via.'
    },
    meRequestPreview () {
      const source = this.activeMode === 'secure-cookie'
        ? 'cookie(HttpOnly) con withCredentials = true'
        : this.activeToken ? `Authorization: Bearer ${this.activeToken.slice(0, 18)}...` : '(sin token accesible)'

      return [
        'GET /api/lab/token-storage/me',
        '',
        `fuente esperada = ${source}`,
        `modo activo = ${this.activeMode}`
      ].join('\n')
    },
    meExplanation () {
      if (this.activeMode === 'secure-cookie') {
        return 'El backend puede autenticar al usuario sin exponer el valor del token a JavaScript. Ese es el beneficio principal del modo HttpOnly en este laboratorio.'
      }

      return 'Cuando el token esta accesible en memoria o localStorage, el backend puede validar /me sin problema, pero la misma facilidad existe para un script malicioso que lo robe y lo reutilice.'
    },
    activeToken () {
      if (this.activeMode === 'secure-memory') {
        return this.memoryToken
      }

      if (this.activeMode === 'vulnerable') {
        return this.localStorageToken
      }

      return ''
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    applyPreset (preset) {
      this.form.username = preset.username
      this.form.password = preset.password
      this.secureMode = preset.secureMode
    },
    extractError (error) {
      return apiMessage(error)
    },
    async loginVulnerable () {
      this.loading.vulnerableLogin = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/token-storage/login`, {
          username: this.form.username,
          password: this.form.password,
          deliveryMode: 'header'
        })

        this.memoryToken = ''
        this.localStorageToken = response.data.accessToken || ''
        window.localStorage.setItem(TOKEN_KEY, this.localStorageToken)
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El token vulnerable se guardo en localStorage.'
        this.vulnerableOk = true
        this.activeMode = 'vulnerable'
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = this.extractError(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerableLogin = false
      }
    },
    async loginSecure () {
      this.loading.secureLogin = true
      try {
        const cookieMode = this.secureMode === 'cookie'
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/token-storage/login`, {
          username: this.form.username,
          password: this.form.password,
          deliveryMode: cookieMode ? 'cookie' : 'header'
        }, {
          withCredentials: cookieMode
        })

        window.localStorage.removeItem(TOKEN_KEY)
        this.localStorageToken = ''
        this.memoryToken = cookieMode ? '' : (response.data.accessToken || '')
        this.secureResult = response.data
        this.secureMessage = cookieMode
          ? 'Login seguro con cookie HttpOnly. El token no queda disponible para JavaScript.'
          : 'Login seguro con token en memoria. Reduce persistencia, pero no oculta el token al mismo JavaScript de la pagina.'
        this.secureOk = true
        this.activeMode = cookieMode ? 'secure-cookie' : 'secure-memory'
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = this.extractError(error)
        this.secureOk = false
      } finally {
        this.loading.secureLogin = false
      }
    },
    readLocalStorageToken () {
      const token = window.localStorage.getItem(TOKEN_KEY) || ''
      this.localStorageToken = token
      this.readState = {
        source: 'localStorage',
        tokenReadable: Boolean(token),
        tokenPreview: token ? `${token.slice(0, 24)}...` : null
      }
      this.readMessage = token
        ? 'JavaScript de la pagina pudo leer el token desde localStorage.'
        : 'No hay token accesible en localStorage.'
    },
    readMemoryToken () {
      const token = this.memoryToken || ''
      this.readState = {
        source: 'memory',
        tokenReadable: Boolean(token),
        tokenPreview: token ? `${token.slice(0, 24)}...` : null,
        note: token ? 'La variable de memoria es visible para el mismo JavaScript de la pagina.' : 'No hay token en memoria.'
      }
      this.readMessage = token
        ? 'JavaScript de la pagina pudo leer el token desde memoria.'
        : this.activeMode === 'secure-cookie'
            ? 'En modo cookie HttpOnly, JavaScript no recibe el valor del token para leerlo.'
            : 'No hay token en memoria.'
    },
    async loadCurrentUser () {
      this.loading.me = true
      try {
        const headers = {}
        if (this.activeMode !== 'secure-cookie' && this.activeToken) {
          headers.Authorization = `Bearer ${this.activeToken}`
        }

        const response = await this.$http.get(`${this.apiBaseUrl}/lab/token-storage/me`, {
          headers,
          withCredentials: this.activeMode === 'secure-cookie'
        })
        this.meResponse = response.data
        this.meMessage = 'El backend valido el token y devolvio el usuario autenticado del laboratorio.'
        this.meOk = true
      } catch (error) {
        this.meResponse = apiPayload(error)
        this.meMessage = this.extractError(error)
        this.meOk = false
      } finally {
        this.loading.me = false
      }
    },
    clearSession () {
      this.memoryToken = ''
      this.localStorageToken = ''
      this.vulnerableResult = null
      this.secureResult = null
      this.meResponse = null
      this.readState = null
      this.readMessage = ''
      this.activeMode = 'none'
      window.localStorage.removeItem(TOKEN_KEY)
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

.didactic-stack {
  min-height: 560px;
  display: flex;
  flex-direction: column;
}

.didactic-stack > * + * {
  margin-top: 14px;
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
