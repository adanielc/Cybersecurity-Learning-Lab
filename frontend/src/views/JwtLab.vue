<template>
  <lab-page-shell
    title="JWT / Validación"
    icon="mdi-key-variant"
    description="El problema no es que un JWT pueda leerse, sino confiar en su contenido sin validar firma, expiración y propósito. Aquí se compara la lectura local de claims con la validación real en servidor."
    vulnerable-endpoint="Lectura local del payload JWT"
    secure-endpoint="POST /api/lab/token-storage/login | GET /api/lab/token-storage/me"
    vulnerable-method="LOCAL"
    secure-method="POST / GET"
    vulnerable-hint="Decodificar base64 no demuestra autenticidad. Un payload manipulado puede parecer válido al cliente."
    secure-hint="El backend verifica firma HS256, exp y purpose antes de aceptar el token."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="Un JWT no está cifrado por defecto. Cualquiera que lo tenga puede leer header y payload. La decisión de acceso debe depender de una verificación criptográfica en servidor, no de lo que el cliente cree haber visto en los claims."
    owasp-label="OWASP A07: Identification and Authentication Failures"
    risk-label="Impacto alto: suplantación de claims, bypass de lógica cliente y abuso de tokens expirados o alterados"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué pasa por detrás</div>
          <p class="mini-text">
            Un atacante puede abrir el JWT, modificar el payload y volver a montarlo. Si una SPA o un backend inseguro
            solo decodifica el token y confía en los claims, el contenido manipulado puede activar lógica privilegiada.
          </p>
        </div>

        <div>
          <div class="mini-title">Lectura local sin validar</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Antipatrón</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>La UI puede mostrar opciones de admin si confía en <code>payload.role</code>.</li>
            <li>Un backend inseguro podría aceptar tokens expirados o con propósito alterado.</li>
            <li>Leer claims es útil para UX, pero no para autorizar acceso.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué cambia</div>
          <p class="mini-text">
            El backend reconstruye la parte firmada, recalcula la firma con su secreto y además comprueba expiración y
            propósito del token antes de usar el <code>username</code> contenido en el payload.
          </p>
        </div>

        <div>
          <div class="mini-title">Validación segura</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decisión del backend</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>Un token firmado correctamente y no expirado permite acceso.</li>
            <li>Un payload alterado sin nueva firma válida se rechaza.</li>
            <li>Un <code>purpose</code> incorrecto o un <code>exp</code> vencido también se rechazan.</li>
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
          Código del backend y antipatrón
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: confiar en claims sin verificar</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureValidationCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: emisión y uso del token del laboratorio</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Login</div>
                <pre class="code-box">{{ issueCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">GET /me</div>
                <pre class="code-box">{{ meCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: emitir un JWT legítimo
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Primero se solicita un token válido al backend. Esto permite ver que el payload es legible por el cliente,
            pero eso no significa que el cliente deba decidir autorizaciones a partir de esos claims.
          </p>

          <v-row>
            <v-col cols="12" md="4">
              <v-text-field
                v-model="username"
                label="Username"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="4">
              <v-text-field
                v-model="password"
                label="Password"
                type="password"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="4">
              <v-select
                v-model="deliveryMode"
                :items="deliveryModes"
                label="Entrega"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="item in issuePresets"
              :key="item.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="applyIssuePreset(item)"
            >
              {{ item.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loadingIssue" @click="issueToken">
                Emitir JWT
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="primary" :disabled="!issuedToken" @click="restoreIssuedToken">
                Restaurar token emitido
              </v-btn>
            </v-col>
          </v-row>

          <v-textarea
            v-model="token"
            label="JWT actual"
            outlined
            dense
            auto-grow
            rows="4"
            class="mt-4"
            hide-details="auto"
          />

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Lectura local del token
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="issueMessage" :type="issueOk ? 'success' : 'error'" outlined dense>
                    {{ issueMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ issuedTokenPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ issueVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(issuedDecodeResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Respuesta del backend
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--safe">{{ loginRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ issueSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(loginResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: manipular el JWT y compararlo con la validación real
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aquí el alumno puede forjar el payload localmente. El objetivo es ver que la lectura sin validación puede
            parecer convincente, mientras que el backend rechaza el token alterado cuando la firma, la expiración o el
            propósito no cuadran.
          </p>

          <div class="payload-actions mb-2">
            <v-btn small outlined color="primary" class="mr-2 mb-2" :disabled="!token" @click="forgeAdminRole">
              Forjar rol ADMIN
            </v-btn>
            <v-btn small outlined color="primary" class="mr-2 mb-2" :disabled="!token" @click="forgeExpiredToken">
              Forzar exp vencido
            </v-btn>
            <v-btn small outlined color="primary" class="mr-2 mb-2" :disabled="!token" @click="forgeWrongPurpose">
              Cambiar purpose
            </v-btn>
          </div>

          <v-alert type="info" outlined dense class="mb-4">
            Si eliges <strong>cookie</strong>, el token no queda accesible desde JavaScript. Para la demo de manipulación,
            usa <strong>header</strong> y un token visible en el textarea.
          </v-alert>

          <v-row>
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loadingDecode" @click="decodeWithoutValidation">
                Decodificar sin validar
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loadingValidate" @click="validateToken">
                Validar en backend
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
                  <v-alert v-if="decodeMessage" :type="decodeOk ? 'success' : 'error'" outlined dense>
                    {{ decodeMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ tamperedTokenPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ decodeExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(localDecodeResult) }}</pre>
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
                  <v-alert v-if="validateMessage" :type="validateOk ? 'success' : 'error'" outlined dense>
                    {{ validateMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ validateRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ validateExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(serverValidationResult) }}</pre>
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
            <li>Valida siempre firma, expiración y propósito en el backend.</li>
            <li>No conviertas <code>payload.role</code> o <code>payload.sub</code> en autorización implícita del lado cliente.</li>
            <li>Usa tokens cortos y scopes o purposes concretos.</li>
            <li>Si el caso lo requiere, combina memoria o cookies HttpOnly con una política XSS estricta.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave</div>
          <p class="mini-text mb-0">
            Un JWT puede ser legible y seguir siendo seguro si el backend lo verifica correctamente. El riesgo aparece
            cuando alguien confunde “puedo leerlo” con “puedo confiar en él”.
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
  name: 'JwtLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      username: 'alice',
      password: 'password123',
      deliveryMode: 'header',
      deliveryModes: ['header', 'cookie'],
      token: '',
      issuedToken: '',
      loginResult: null,
      issuedDecodeResult: null,
      localDecodeResult: null,
      serverValidationResult: null,
      issueMessage: '',
      decodeMessage: '',
      validateMessage: '',
      issueOk: false,
      decodeOk: false,
      validateOk: false,
      loadingIssue: false,
      loadingDecode: false,
      loadingValidate: false,
      issuePresets: [
        { label: 'alice header', username: 'alice', password: 'password123', deliveryMode: 'header' },
        { label: 'admin header', username: 'admin', password: 'adminpass', deliveryMode: 'header' },
        { label: 'alice cookie', username: 'alice', password: 'password123', deliveryMode: 'cookie' }
      ],
      vulnerableCode: [
        'const payload = JSON.parse(atob(token.split(".")[1]));',
        'if (payload.role === "ADMIN") {',
        '    enableAdminUI();',
        '}',
        '// No verifica firma, exp ni purpose'
      ].join('\n'),
      secureValidationCode: [
        'private DecodedToken verifyAndDecode(String token) {',
        '    String[] parts = token.split("\\.");',
        '    String unsignedToken = parts[0] + "." + parts[1];',
        '    if (!MessageDigest.isEqual(sign(unsignedToken), parts[2])) throw 401;',
        '    if (Instant.now().getEpochSecond() > exp) throw 401;',
        '    if (!JWT_PURPOSE.equals(purpose)) throw 401;',
        '    return new DecodedToken(username, Instant.ofEpochSecond(exp));',
        '}'
      ].join('\n'),
      issueCode: [
        'public LoginResult login(TokenStorageLoginRequest request) {',
        '    LabAccount account = authenticate(request.username(), request.password());',
        '    String token = createJwt(account, issuedAt, expiresAt);',
        '    return new LoginResult(response, token);',
        '}'
      ].join('\n'),
      meCode: [
        'public TokenStorageMeResponse me(String authorizationHeader, String cookieToken) {',
        '    ResolvedToken resolvedToken = extractToken(authorizationHeader, cookieToken);',
        '    DecodedToken decoded = verifyAndDecode(resolvedToken.token());',
        '    LabAccount account = accounts.get(decoded.username());',
        '    return new TokenStorageMeResponse(...);',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'SPAs que leen claims',
          text: 'Interfaces que decodifican el token para mostrar roles o menús pueden terminar confiando en un payload sin verificar.'
        },
        {
          title: 'Middlewares caseros',
          text: 'Backends que solo hacen base64 decode del payload y extraen username o role sin recalcular firma.'
        },
        {
          title: 'Microservicios internos',
          text: 'Tokens reenviados entre servicios sin validar exp o purpose pueden vivir más tiempo o en contextos no previstos.'
        },
        {
          title: 'APIs con JWT reutilizado',
          text: 'Aceptar cualquier JWT firmado, sin distinguir propósito o audiencia, amplía el impacto de un token filtrado.'
        }
      ],
      remediationPoints: [
        'Validar firma y expiración en servidor.',
        'No confiar en claims sin verificar el token completo.',
        'Comprobar propósito o audiencia del token.',
        'Mantener corta la duración del access token.'
      ],
      sideBullets: [
        'Header y payload son legibles; la firma es lo que protege la integridad.',
        'La decisión de acceso siempre debe hacerse en servidor.'
      ]
    }
  },
  computed: {
    loginRequestPreview () {
      return [
        'POST /api/lab/token-storage/login',
        '',
        `{ "username": "${this.username || '(vacío)'}", "password": "***", "deliveryMode": "${this.deliveryMode}" }`
      ].join('\n')
    },
    issuedTokenPreview () {
      if (!this.issuedToken) {
        return this.deliveryMode === 'cookie'
          ? 'Modo cookie: el token se entrega en HttpOnly cookie y no queda accesible desde JavaScript.'
          : 'Aún no se ha emitido un token visible.'
      }

      return [
        'JWT emitido:',
        this.issuedToken,
        '',
        'Header y payload pueden leerse localmente aunque la firma siga siendo necesaria.'
      ].join('\n')
    },
    tamperedTokenPreview () {
      return [
        'JWT actual en el textarea:',
        this.token || '(vacío)',
        '',
        'La decodificación local mostrará claims aunque la firma ya no corresponda.'
      ].join('\n')
    },
    validateRequestPreview () {
      const source = this.shouldUseCookie ? 'cookie(HttpOnly)' : 'Authorization: Bearer <token>'
      return [
        'GET /api/lab/token-storage/me',
        '',
        `Fuente del token: ${source}`,
        this.shouldUseCookie ? 'withCredentials = true' : `Authorization = ${this.token ? 'Bearer ' + this.token.slice(0, 24) + '...' : '(vacío)'}`
      ].join('\n')
    },
    vulnerablePreview () {
      return [
        'token.split(".")[1] -> payload base64url',
        'base64url decode -> JSON legible',
        'leer role/sub/exp en cliente = posible',
        'confiar en esos claims = error de validación'
      ].join('\n')
    },
    vulnerableDecisionPreview () {
      const role = this.localDecodedRole || this.issuedDecodedRole || '(desconocido)'
      return [
        `payload.role = ${role}`,
        'if payload.role === "ADMIN" -> mostrar panel admin',
        'if payload.exp parece futuro -> asumir sesión válida',
        'firma comprobada = no'
      ].join('\n')
    },
    securePreview () {
      return [
        '1. Extraer token de Authorization o cookie',
        '2. Recalcular firma HS256 del header.payload',
        '3. Comparar firma recibida vs firma esperada',
        '4. Validar exp y purpose',
        '5. Cargar usuario real del backend'
      ].join('\n')
    },
    secureDecisionPreview () {
      return [
        `firma válida = ${this.signatureLooksValid}`,
        `purpose esperado = token-storage-lab`,
        `exp legible = ${this.localDecodedExp || '(desconocido)'}`,
        'si cualquiera falla -> 401 Unauthorized'
      ].join('\n')
    },
    issueVulnerableExplanation () {
      if (this.deliveryMode === 'cookie' && !this.issuedToken) {
        return 'En modo cookie el navegador recibe el token, pero JavaScript no puede leerlo directamente si se entrega como HttpOnly. Eso reduce la superficie para lectura local y manipulación desde la SPA.'
      }

      return 'El cliente puede leer header y payload del JWT emitido. Eso es normal. El fallo empezaría si la interfaz o un backend inseguro convirtieran esos claims en autorización sin verificar la firma.'
    },
    issueSecureExplanation () {
      return 'El backend autentica credenciales, emite un JWT con exp y purpose concretos, y luego espera volver a validarlo en el endpoint /me antes de usarlo para acceso.'
    },
    decodeExplanation () {
      const role = this.localDecodedRole
      if (role === 'ADMIN') {
        return 'La lectura local ve role = ADMIN y podría activar lógica privilegiada aunque el token haya sido manipulado. Esta es la trampa didáctica del laboratorio.'
      }

      return 'La decodificación local solo demuestra que el payload tiene forma válida y puede leerse. No demuestra autenticidad ni vigencia del token.'
    },
    validateExplanation () {
      if (this.validateOk) {
        return 'El backend aceptó este token porque la firma, la expiración y el propósito eran válidos para el laboratorio.'
      }

      return 'Si el token fue manipulado, expiró o trae un purpose incorrecto, el backend debe rechazarlo aunque la decodificación local siga mostrando claims aparentemente coherentes.'
    },
    shouldUseCookie () {
      return this.deliveryMode === 'cookie' && !this.token.trim()
    },
    issuedDecodedRole () {
      return this.issuedDecodeResult && this.issuedDecodeResult.payload ? this.issuedDecodeResult.payload.role : ''
    },
    localDecodedRole () {
      return this.localDecodeResult && this.localDecodeResult.payload ? this.localDecodeResult.payload.role : ''
    },
    localDecodedExp () {
      return this.localDecodeResult && this.localDecodeResult.payload ? this.localDecodeResult.payload.exp : ''
    },
    signatureLooksValid () {
      return this.token && this.issuedToken && this.token === this.issuedToken ? 'sí (mismo token emitido)' : 'desconocido desde cliente'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    applyIssuePreset (item) {
      this.username = item.username
      this.password = item.password
      this.deliveryMode = item.deliveryMode
    },
    base64UrlDecode (value) {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
      const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4)
      return atob(padded)
    },
    base64UrlEncode (value) {
      return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
    },
    parseToken (token) {
      const parts = String(token || '').trim().split('.')
      if (parts.length !== 3) {
        throw new Error('JWT inválido')
      }

      const header = JSON.parse(this.base64UrlDecode(parts[0]))
      const payload = JSON.parse(this.base64UrlDecode(parts[1]))
      return {
        parts,
        header,
        payload,
        signature: parts[2]
      }
    },
    buildTamperedToken (mutator) {
      const parsed = this.parseToken(this.token)
      const payload = { ...parsed.payload }
      mutator(payload)
      const encodedHeader = parsed.parts[0]
      const encodedPayload = this.base64UrlEncode(JSON.stringify(payload))
      return `${encodedHeader}.${encodedPayload}.${parsed.signature}`
    },
    restoreIssuedToken () {
      this.token = this.issuedToken
    },
    forgeAdminRole () {
      try {
        this.token = this.buildTamperedToken(payload => {
          payload.role = 'ADMIN'
          payload.username = payload.username || this.username || 'alice'
        })
      } catch (error) {
        this.decodeMessage = error.message || 'No se pudo manipular el token'
        this.decodeOk = false
      }
    },
    forgeExpiredToken () {
      try {
        this.token = this.buildTamperedToken(payload => {
          payload.exp = Math.floor(Date.now() / 1000) - 300
        })
      } catch (error) {
        this.decodeMessage = error.message || 'No se pudo manipular el token'
        this.decodeOk = false
      }
    },
    forgeWrongPurpose () {
      try {
        this.token = this.buildTamperedToken(payload => {
          payload.purpose = 'other-lab'
        })
      } catch (error) {
        this.decodeMessage = error.message || 'No se pudo manipular el token'
        this.decodeOk = false
      }
    },
    async issueToken () {
      this.loadingIssue = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/token-storage/login`, {
          username: this.username,
          password: this.password,
          deliveryMode: this.deliveryMode
        }, {
          withCredentials: this.deliveryMode === 'cookie'
        })
        this.loginResult = response.data
        this.issuedToken = response.data.accessToken || ''
        this.token = this.issuedToken
        this.issuedDecodeResult = this.issuedToken ? this.parseToken(this.issuedToken) : null
        this.issueMessage = this.issuedToken
          ? 'El backend emitió un JWT válido para el laboratorio.'
          : 'El backend emitió el token en cookie HttpOnly; por eso no aparece accesible en el cuerpo.'
        this.issueOk = true
      } catch (error) {
        this.loginResult = apiPayload(error)
        this.issuedToken = ''
        this.token = ''
        this.issuedDecodeResult = null
        this.issueMessage = apiMessage(error)
        this.issueOk = false
      } finally {
        this.loadingIssue = false
      }
    },
    async decodeWithoutValidation () {
      this.loadingDecode = true
      try {
        this.localDecodeResult = this.parseToken(this.token)
        this.decodeMessage = 'La decodificación local leyó header y payload sin verificar firma, exp ni purpose.'
        this.decodeOk = true
      } catch (error) {
        this.localDecodeResult = { error: error.message || 'JWT inválido' }
        this.decodeMessage = error.message || 'JWT inválido'
        this.decodeOk = false
      } finally {
        this.loadingDecode = false
      }
    },
    async validateToken () {
      this.loadingValidate = true
      try {
        const config = this.shouldUseCookie
          ? { withCredentials: true }
          : { headers: this.token.trim() ? { Authorization: `Bearer ${this.token.trim()}` } : {} }
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/token-storage/me`, config)
        this.serverValidationResult = response.data
        this.validateMessage = 'El backend validó la firma, la expiración y el propósito del token.'
        this.validateOk = true
      } catch (error) {
        this.serverValidationResult = apiPayload(error)
        this.validateMessage = apiMessage(error)
        this.validateOk = false
      } finally {
        this.loadingValidate = false
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
