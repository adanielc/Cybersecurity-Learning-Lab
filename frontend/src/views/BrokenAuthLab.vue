<template>
  <lab-page-shell
    title="Broken Authentication"
    icon="mdi-lock-alert"
    description="Este laboratorio compara una autenticacion que revela demasiado al atacante con otra que responde de forma generica, endurece las contrasenas y frena intentos repetidos."
    vulnerable-endpoint="POST /api/lab/auth/login-insecure | POST /api/lab/auth/register-insecure"
    secure-endpoint="POST /api/lab/auth/login-secure | POST /api/lab/auth/register-secure"
    vulnerable-method="POST"
    secure-method="POST"
    vulnerable-hint="La version vulnerable revela si el usuario existe, acepta contrasenas debiles en registro y no frena fuerza bruta en login."
    secure-hint="La version segura devuelve errores genericos, exige contrasenas mas fuertes y aplica limite de intentos."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="Broken Authentication no suele ser un unico bug. Normalmente aparece como combinacion de mensajes demasiado precisos, credenciales debiles, almacenamiento pobre de passwords y falta de controles frente a fuerza bruta."
    owasp-label="OWASP A07:2021 Identification and Authentication Failures"
    risk-label="Impacto alto: enumeracion, acceso indebido y toma de cuentas"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que pasa por detras</div>
          <p class="mini-text">
            El backend vulnerable distingue entre <code>usuario no encontrado</code> y <code>contrasena incorrecta</code>.
            Ademas, en registro acepta claves triviales y mantiene passwords en claro dentro del laboratorio.
          </p>
        </div>

        <div>
          <div class="mini-title">Flujo vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Lo que aprende un atacante</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableEffectPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>Permite enumerar cuentas validas probando usernames.</li>
            <li>Facilita fuerza bruta porque no hay freno real en login inseguro.</li>
            <li>El registro admite contrasenas pobres, faciles de adivinar o reutilizar.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que cambia</div>
          <p class="mini-text">
            La version segura devuelve un mensaje unico para no confirmar si la cuenta existe, valida una politica
            minima de password y aplica rate limiting por usuario e IP para frenar intentos repetidos.
          </p>
        </div>

        <div>
          <div class="mini-title">Flujo seguro</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Senales que ya no recibe el atacante</div>
          <pre class="sql-box sql-box--safe">{{ secureEffectPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>No se confirma si el username existe o no.</li>
            <li>Las contrasenas se hashean con BCrypt antes de guardarse.</li>
            <li>Tras varios fallos seguidos, el login responde con <code>429</code>.</li>
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
          Cuentas del laboratorio
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="context-grid">
            <div v-for="account in labAccounts" :key="account.username" class="context-item">
              <div class="context-item__title">{{ account.username }}</div>
              <div class="context-item__text">Rol: {{ account.role }} | Password: {{ account.password }}</div>
            </div>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Codigo del backend
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: login</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableLoginCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureLoginCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: registro</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableRegisterCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureRegisterCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: login, enumeracion y fuerza bruta
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            El objetivo es ver si la respuesta del backend ayuda a descubrir cuentas validas o si dificulta esa tarea.
            Con las mismas credenciales, compara el mensaje vulnerable, el mensaje seguro y el bloqueo por intentos.
          </p>

          <v-row>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="login.username"
                label="Username"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="login.password"
                label="Password"
                type="password"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="preset in loginPresets"
              :key="preset.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="applyLoginPreset(preset)"
            >
              {{ preset.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="4">
              <v-btn block color="warning" :loading="loading.insecureLogin" @click="loginInsecure">
                Login vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="4">
              <v-btn block color="success" :loading="loading.secureLogin" @click="loginSecure">
                Login seguro
              </v-btn>
            </v-col>
            <v-col cols="12" md="4">
              <v-btn block outlined color="secondary" :loading="loading.secureBurst" @click="runSecureBurst">
                Repetir 6 fallos en seguro
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
                  <v-alert v-if="loginInsecureMessage" :type="loginInsecureOk ? 'success' : 'error'" outlined dense>
                    {{ loginInsecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ loginRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ loginInsecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(loginInsecureResult) }}</pre>
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

                  <pre class="sql-box sql-box--safe">{{ secureLoginRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ loginSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(loginSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>

          <v-card outlined class="mt-4 burst-card">
            <v-card-title class="subtitle-2">
              Historial de intentos seguros
            </v-card-title>
            <v-divider />
            <v-card-text>
              <pre class="json-box">{{ pretty(burstResults) }}</pre>
            </v-card-text>
          </v-card>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: registro y politicas de password
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aqui se compara si el backend acepta passwords triviales y si devuelve informacion util sobre el motivo del
            fallo. La version segura debe rechazar tanto claves pobres como usernames repetidos sin revelar demasiado.
          </p>

          <v-row>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="register.username"
                label="Username"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="register.displayName"
                label="Display name"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="register.email"
                label="Email"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="register.password"
                label="Password"
                type="password"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="preset in registerPresets"
              :key="preset.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="applyRegisterPreset(preset)"
            >
              {{ preset.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.insecureRegister" @click="registerInsecure">
                Registro vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureRegister" @click="registerSecure">
                Registro seguro
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
                  <v-alert v-if="registerInsecureMessage" :type="registerInsecureOk ? 'success' : 'error'" outlined dense>
                    {{ registerInsecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ registerRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ registerInsecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(registerInsecureResult) }}</pre>
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
                  <v-alert v-if="registerSecureMessage" :type="registerSecureOk ? 'success' : 'error'" outlined dense>
                    {{ registerSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ secureRegisterRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ registerSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(registerSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>
    </template>
  </lab-page-shell>
</template>

<script>
import LabPageShell from '../components/LabPageShell.vue'

const API_BASE_URL = process.env.VUE_APP_API_BASE_URL || 'http://localhost:8082/api'

const emptyAuthResult = () => ({
  success: false,
  message: '',
  token: '',
  username: '',
  email: '',
  displayName: '',
  role: ''
})

export default {
  name: 'BrokenAuthLab',
  components: { LabPageShell },
  data () {
    return {
      remediationPoints: [
        'Devuelve mensajes de error genericos en login y registro para no confirmar si una cuenta existe.',
        'Hashea passwords con un algoritmo adaptativo como BCrypt, Argon2 o scrypt.',
        'Exige una politica minima de password y evita aceptar claves obvias o demasiado cortas.',
        'Aplica rate limiting, bloqueo progresivo o desafios adicionales frente a fuerza bruta.',
        'Registra intentos anómalos y separa autenticacion, autorizacion y gestion de sesiones.'
      ],
      sideBullets: [
        'La enumeracion de usuarios reduce mucho el coste del ataque posterior.',
        'Una password debil convierte un login sin rate limiting en un objetivo facil.',
        'El mensaje correcto para el usuario no siempre es el mensaje mas detallado para el atacante.'
      ],
      commonPlaces: [
        {
          title: 'Pantallas de login',
          text: 'Mensajes distintos para usuario inexistente y password incorrecta permiten descubrir cuentas reales.'
        },
        {
          title: 'Formularios de registro',
          text: 'Aceptar passwords debiles o devolver el motivo exacto del fallo puede facilitar abuso y enumeracion.'
        },
        {
          title: 'APIs moviles y SPA',
          text: 'Los endpoints JSON suelen exponer mensajes y codigos que un atacante puede automatizar con facilidad.'
        },
        {
          title: 'Portales de administracion',
          text: 'Si no hay freno de intentos, un atacante puede combinar credenciales filtradas y fuerza bruta.'
        }
      ],
      labAccounts: [
        { username: 'admin', role: 'ADMIN', password: 'admin123' },
        { username: 'alice', role: 'USER', password: 'password123' },
        { username: 'bob', role: 'USER', password: 'password123' },
        { username: 'auditor', role: 'AUDITOR', password: 'audit123' }
      ],
      loginPresets: [
        { label: 'Usuario inexistente', username: 'ghost', password: 'whatever123' },
        { label: 'Usuario real + password mal', username: 'alice', password: 'wrongpass' },
        { label: 'Credenciales validas', username: 'alice', password: 'password123' },
        { label: 'Admin + password mal', username: 'admin', password: 'guessme' }
      ],
      registerPresets: [
        {
          label: 'Password debil',
          username: 'student-weak',
          displayName: 'Student Weak',
          email: 'student-weak@example.com',
          password: '1234'
        },
        {
          label: 'Password fuerte',
          username: 'student-strong',
          displayName: 'Student Strong',
          email: 'student-strong@example.com',
          password: 'StrongPass1!'
        },
        {
          label: 'Usuario repetido',
          username: 'alice',
          displayName: 'Alice Clone',
          email: 'alice-clone@example.com',
          password: 'StrongPass1!'
        }
      ],
      login: {
        username: 'ghost',
        password: 'whatever123'
      },
      register: {
        username: 'student-weak',
        displayName: 'Student Weak',
        email: 'student-weak@example.com',
        password: '1234'
      },
      loading: {
        insecureLogin: false,
        secureLogin: false,
        secureBurst: false,
        insecureRegister: false,
        secureRegister: false
      },
      loginInsecureResult: emptyAuthResult(),
      loginSecureResult: emptyAuthResult(),
      registerInsecureResult: emptyAuthResult(),
      registerSecureResult: emptyAuthResult(),
      burstResults: []
    }
  },
  computed: {
    vulnerablePreview () {
      return [
        'POST /api/lab/auth/login-insecure',
        '{',
        '  "username": "alice",',
        '  "password": "wrongpass"',
        '}',
        '',
        'if (!user) -> 401 "Usuario no encontrado"',
        'if (password mal) -> 401 "Contrasena incorrecta"'
      ].join('\n')
    },
    securePreview () {
      return [
        'POST /api/lab/auth/login-secure',
        '{',
        '  "username": "alice",',
        '  "password": "wrongpass"',
        '}',
        '',
        'if login falla -> 401 "Credenciales invalidas"',
        'if exceso de intentos -> 429 "Demasiados intentos"'
      ].join('\n')
    },
    vulnerableEffectPreview () {
      return [
        'ghost + cualquier password   -> usuario no encontrado',
        'alice + password incorrecta  -> contrasena incorrecta',
        '',
        'Conclusion: el atacante ya sabe que alice existe.'
      ].join('\n')
    },
    secureEffectPreview () {
      return [
        'ghost + cualquier password  -> credenciales invalidas',
        'alice + password incorrecta -> credenciales invalidas',
        '',
        'Conclusion: el backend no confirma si la cuenta existe.'
      ].join('\n')
    },
    vulnerableLoginCode () {
      return [
        'InsecureUser user = insecureUsers.get(normalize(request.username()));',
        'if (user == null) {',
        '  throw 401 "Usuario no encontrado";',
        '}',
        'if (!Objects.equals(user.password(), request.password())) {',
        '  throw 401 "Contrasena incorrecta";',
        '}',
        'return token(user);'
      ].join('\n')
    },
    secureLoginCode () {
      return [
        'String key = secureKey(request.username(), clientIp);',
        'if (isRateLimited(key)) {',
        '  throw 429 "Demasiados intentos";',
        '}',
        'boolean valid = user != null && passwordEncoder.matches(...);',
        'if (!valid) {',
        '  registerFailure(key);',
        '  throw 401 "Credenciales invalidas";',
        '}',
        'return token(user);'
      ].join('\n')
    },
    vulnerableRegisterCode () {
      return [
        'if (insecureUsers.containsKey(username)) {',
        '  throw 409 "El usuario ya existe";',
        '}',
        'insecureUsers.put(username, new InsecureUser(..., request.password()));',
        'return token(newUser);'
      ].join('\n')
    },
    secureRegisterCode () {
      return [
        'if (!strongPassword(request.password())) {',
        '  throw 400 "No se pudo completar el registro";',
        '}',
        'if (secureUsers.containsKey(username)) {',
        '  throw 400 "No se pudo completar el registro";',
        '}',
        'secureUsers.put(username, new SecureUser(..., passwordEncoder.encode(...)));',
        'return token(newUser);'
      ].join('\n')
    },
    loginRequestPreview () {
      return [
        'POST /api/lab/auth/login-insecure',
        JSON.stringify(this.login, null, 2)
      ].join('\n')
    },
    secureLoginRequestPreview () {
      return [
        'POST /api/lab/auth/login-secure',
        JSON.stringify(this.login, null, 2)
      ].join('\n')
    },
    registerRequestPreview () {
      return [
        'POST /api/lab/auth/register-insecure',
        JSON.stringify(this.register, null, 2)
      ].join('\n')
    },
    secureRegisterRequestPreview () {
      return [
        'POST /api/lab/auth/register-secure',
        JSON.stringify(this.register, null, 2)
      ].join('\n')
    },
    loginInsecureOk () {
      return Boolean(this.loginInsecureResult && this.loginInsecureResult.success)
    },
    loginSecureOk () {
      return Boolean(this.loginSecureResult && this.loginSecureResult.success)
    },
    registerInsecureOk () {
      return Boolean(this.registerInsecureResult && this.registerInsecureResult.success)
    },
    registerSecureOk () {
      return Boolean(this.registerSecureResult && this.registerSecureResult.success)
    },
    loginInsecureMessage () {
      return this.loginInsecureResult.message || ''
    },
    loginSecureMessage () {
      return this.loginSecureResult.message || ''
    },
    registerInsecureMessage () {
      return this.registerInsecureResult.message || ''
    },
    registerSecureMessage () {
      return this.registerSecureResult.message || ''
    },
    loginInsecureExplanation () {
      if (!this.loginInsecureMessage) {
        return 'Todavia no se ha ejecutado el login vulnerable.'
      }

      if (this.loginInsecureOk) {
        return 'Con credenciales validas, el login vulnerable autentica y emite token. El problema aparece sobre todo cuando falla, porque el mensaje distingue demasiado.'
      }

      if (/no encontrado/i.test(this.loginInsecureMessage)) {
        return 'La respuesta confirma que el username no existe. Eso permite enumerar cuentas validas antes de probar passwords.'
      }

      if (/incorrecta/i.test(this.loginInsecureMessage)) {
        return 'La respuesta confirma que la cuenta existe pero la password es incorrecta. Ya has reducido el problema a adivinar solo la clave.'
      }

      return 'El backend vulnerable esta filtrando detalle operativo que un atacante puede automatizar.'
    },
    loginSecureExplanation () {
      if (!this.loginSecureMessage) {
        return 'Todavia no se ha ejecutado el login seguro.'
      }

      if (this.loginSecureOk) {
        return 'Con credenciales validas el login seguro autentica igual, pero cuando falla responde de forma generica y conserva menos informacion util para el atacante.'
      }

      if (/demasiados intentos/i.test(this.loginSecureMessage)) {
        return 'El backend ha activado el rate limiting para este usuario e IP. Eso encarece la fuerza bruta y reduce su velocidad.'
      }

      return 'La respuesta segura no confirma si el username existe o si el error real esta en la password.'
    },
    registerInsecureExplanation () {
      if (!this.registerInsecureMessage) {
        return 'Todavia no se ha ejecutado el registro vulnerable.'
      }

      if (this.registerInsecureOk) {
        return 'El registro vulnerable acepta la password tal como llega, incluso si es trivial. Eso facilita cuentas debiles desde el primer momento.'
      }

      if (/ya existe/i.test(this.registerInsecureMessage)) {
        return 'La respuesta confirma que el username ya estaba registrado. Tambien aqui se filtra informacion util para enumeracion.'
      }

      return 'El flujo vulnerable no endurece la autenticacion desde el alta de usuario.'
    },
    registerSecureExplanation () {
      if (!this.registerSecureMessage) {
        return 'Todavia no se ha ejecutado el registro seguro.'
      }

      if (this.registerSecureOk) {
        return 'El registro seguro ha aceptado una password que cumple politica minima y la almacenara hasheada en el laboratorio seguro.'
      }

      return 'La respuesta segura usa el mismo mensaje tanto para password debil como para usuario repetido. Asi evita dar pistas innecesarias.'
    }
  },
  methods: {
    pretty (value) {
      return JSON.stringify(value, null, 2)
    },
    applyLoginPreset (preset) {
      this.login = {
        username: preset.username,
        password: preset.password
      }
    },
    applyRegisterPreset (preset) {
      this.register = {
        username: preset.username,
        displayName: preset.displayName,
        email: preset.email,
        password: preset.password
      }
    },
    async loginInsecure () {
      this.loading.insecureLogin = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/login-insecure`, this.login)
        this.loginInsecureResult = response.data
      } catch (error) {
        this.loginInsecureResult = this.extractResult(error)
      } finally {
        this.loading.insecureLogin = false
      }
    },
    async loginSecure () {
      this.loading.secureLogin = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/login-secure`, this.login)
        this.loginSecureResult = response.data
      } catch (error) {
        this.loginSecureResult = this.extractResult(error)
      } finally {
        this.loading.secureLogin = false
      }
    },
    async runSecureBurst () {
      this.loading.secureBurst = true
      this.burstResults = []
      const payload = { ...this.login }

      for (let attempt = 1; attempt <= 6; attempt += 1) {
        try {
          const response = await this.$http.post(`${API_BASE_URL}/lab/auth/login-secure`, payload)
          this.burstResults.push({
            attempt,
            status: 200,
            message: response.data.message
          })
          this.loginSecureResult = response.data
        } catch (error) {
          const result = this.extractResult(error)
          this.burstResults.push({
            attempt,
            status: result.status || 0,
            message: result.message
          })
          this.loginSecureResult = result
        }
      }

      this.loading.secureBurst = false
    },
    async registerInsecure () {
      this.loading.insecureRegister = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/register-insecure`, this.register)
        this.registerInsecureResult = response.data
      } catch (error) {
        this.registerInsecureResult = this.extractResult(error)
      } finally {
        this.loading.insecureRegister = false
      }
    },
    async registerSecure () {
      this.loading.secureRegister = true
      try {
        const response = await this.$http.post(`${API_BASE_URL}/lab/auth/register-secure`, this.register)
        this.registerSecureResult = response.data
      } catch (error) {
        this.registerSecureResult = this.extractResult(error)
      } finally {
        this.loading.secureRegister = false
      }
    },
    extractResult (error) {
      if (error.response) {
        return {
          success: false,
          message: (error.response.data && error.response.data.message) || `HTTP ${error.response.status}`,
          token: '',
          username: '',
          email: '',
          displayName: '',
          role: '',
          status: error.response.status
        }
      }

      return {
        success: false,
        message: 'No se pudo completar la operacion.',
        token: '',
        username: '',
        email: '',
        displayName: '',
        role: '',
        status: 0
      }
    }
  }
}
</script>

<style scoped>
.didactic-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-height: 520px;
}

.mini-title {
  font-size: 0.9rem;
  font-weight: 700;
  color: #111827;
  margin-bottom: 6px;
}

.mini-text {
  margin: 0;
  color: #4b5563;
  line-height: 1.6;
}

.sql-box,
.code-box,
.json-box {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.85rem;
  line-height: 1.55;
  border-radius: 8px;
  padding: 14px;
  background: #0f172a;
  color: #e5eefc;
}

.sql-box--danger {
  background: #fff1f2;
  color: #9f1239;
  border: 1px solid #fecdd3;
}

.sql-box--safe {
  background: #f0fdf4;
  color: #166534;
  border: 1px solid #bbf7d0;
}

.code-box {
  min-height: 200px;
}

.json-box {
  background: #111827;
  color: #e5e7eb;
  min-height: 120px;
}

.code-caption {
  font-size: 0.8rem;
  font-weight: 700;
  color: #374151;
  margin-bottom: 8px;
  text-transform: uppercase;
}

.code-caption--danger {
  color: #b91c1c;
}

.code-caption--safe {
  color: #15803d;
}

.flow-block + .flow-block {
  margin-top: 24px;
}

.flow-block__title {
  font-weight: 700;
  color: #111827;
  margin-bottom: 12px;
}

.flow-block--spaced {
  margin-top: 8px;
}

.context-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}

.context-item {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 14px;
  background: #ffffff;
}

.context-item__title {
  font-size: 0.9rem;
  font-weight: 700;
  color: #111827;
  margin-bottom: 6px;
}

.context-item__text {
  color: #4b5563;
  line-height: 1.5;
  font-size: 0.9rem;
}

.payload-actions {
  margin-top: 12px;
}

.result-card {
  border-radius: 8px;
}

.full-height {
  height: 100%;
}

.explanation-box {
  margin-top: 14px;
  border-radius: 8px;
  padding: 12px 14px;
  font-size: 0.92rem;
  line-height: 1.55;
}

.explanation-box--danger {
  background: #fff7ed;
  border: 1px solid #fed7aa;
  color: #9a3412;
}

.explanation-box--safe {
  background: #eff6ff;
  border: 1px solid #bfdbfe;
  color: #1d4ed8;
}

.compact-list {
  margin: 0;
  padding-left: 18px;
}

.compact-list li + li {
  margin-top: 6px;
}

.burst-card {
  border-radius: 8px;
}
</style>
