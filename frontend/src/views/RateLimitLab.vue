<template>
  <lab-page-shell
    title="Rate Limiting"
    icon="mdi-timer-sand"
    description="El problema aparece cuando un endpoint sensible acepta intentos ilimitados en poco tiempo. Aqui se compara un login sin freno con otro que corta el abuso temporalmente mediante una ventana de intentos y HTTP 429."
    vulnerable-endpoint="POST /api/lab/rate-limit/login-insecure"
    secure-endpoint="POST /api/lab/rate-limit/login-secure"
    vulnerable-method="POST"
    secure-method="POST"
    vulnerable-hint="La version vulnerable permite repetir intentos sin coste hasta acertar la credencial."
    secure-hint="La version segura cuenta fallos por IP y usuario dentro de una ventana temporal y devuelve 429 cuando se supera el umbral."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="Rate limiting no arregla unas credenciales debiles, pero reduce la velocidad de automatizacion y hace mas costosa una fuerza bruta o un credential stuffing."
    owasp-label="OWASP API4:2023 Unrestricted Resource Consumption"
    risk-label="Impacto medio/alto: fuerza bruta y automatizacion de intentos"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que pasa por detras</div>
          <p class="mini-text">
            El backend valida usuario y contrasena, pero no recuerda cuantos fallos seguidos llegan desde la misma IP
            y el mismo username. Un script puede repetir peticiones hasta acertar o agotar un diccionario de claves.
          </p>
        </div>

        <div>
          <div class="mini-title">POST vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decision del backend</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>Un atacante puede probar muchas claves para el mismo usuario.</li>
            <li>La misma IP puede repetir intentos sin recibir enfriamiento temporal.</li>
            <li>El problema no es el metodo POST, sino no controlar la frecuencia.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que cambia</div>
          <p class="mini-text">
            La version segura mantiene un bucket temporal por IP y username. Cada fallo suma un intento dentro de una
            ventana de un minuto y, al llegar al umbral, el backend responde con <code>429 Too Many Requests</code>.
          </p>
        </div>

        <div>
          <div class="mini-title">POST seguro</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decision del backend</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>Los primeros fallos actualizan el contador y reducen intentos restantes.</li>
            <li>Al superar el umbral, el backend corta temporalmente la automatizacion.</li>
            <li>Un login correcto limpia el bucket para esa combinacion de IP y usuario.</li>
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
          Codigo del backend
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: login sin limite frente a login protegido</div>
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
            <div class="flow-block__title">Escenario 2: bucket temporal por IP y usuario</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption">Clave del bucket</div>
                <pre class="code-box">{{ bucketCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption">Helpers didacticos</div>
                <pre class="code-box">{{ inspectCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: POST de login individual
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aqui se compara una sola llamada de login con la misma combinacion de IP, usuario y contrasena. El
            endpoint vulnerable responde siempre sin frenar la repeticion; el seguro actualiza el contador del bucket.
          </p>

          <v-row>
            <v-col cols="12" md="4">
              <v-text-field
                v-model="clientIp"
                label="IP atacante simulada"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
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
                outlined
                dense
                hide-details="auto"
                type="password"
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

          <div class="bucket-strip mt-2">
            <v-btn small outlined color="secondary" :loading="loading.state" @click="inspectState">
              Ver bucket
            </v-btn>
            <v-btn small outlined color="secondary" :loading="loading.reset" @click="resetState">
              Resetear bucket
            </v-btn>
            <span class="bucket-strip__text">Clave actual: {{ bucketLabel }}</span>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerable" @click="loginVulnerable">
                Ejecutar POST vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secure" @click="loginSecure">
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
                  Resultado seguro y bucket
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
                  <div class="mini-title mt-4">Estado del bucket</div>
                  <div class="bucket-overview">
                    <div class="bucket-overview__item">
                      <span class="bucket-overview__label">Clave actual</span>
                      <strong>{{ bucketLabel }}</strong>
                    </div>
                    <div class="bucket-overview__item">
                      <span class="bucket-overview__label">IPs activas vistas</span>
                      <strong>{{ bucketEntries.length }}</strong>
                    </div>
                    <div class="bucket-overview__item">
                      <span class="bucket-overview__label">Fallos IP actual</span>
                      <strong>{{ stateSummary ? stateSummary.failedAttempts : 0 }}</strong>
                    </div>
                  </div>
                  <div class="mini-title mt-4">IPs registradas en el bucket</div>
                  <v-alert v-if="!bucketEntries.length" type="info" outlined dense>
                    Todavia no hay IPs registradas para este username dentro del bucket visible.
                  </v-alert>
                  <div v-else class="bucket-entry-list">
                    <div
                      v-for="entry in bucketEntries"
                      :key="entry.bucketKey"
                      class="bucket-entry"
                      :class="{ 'bucket-entry--current': entry.clientIp === normalizedClientIp, 'bucket-entry--limited': entry.limited }"
                    >
                      <div class="bucket-entry__header">
                        <strong>{{ entry.clientIp }}</strong>
                        <span>{{ entry.limited ? 'Limitada' : 'Activa' }}</span>
                      </div>
                      <div class="bucket-entry__meta">Bucket: {{ entry.bucketKey }}</div>
                      <div class="bucket-entry__stats">
                        <span>Fallos: {{ entry.failedAttempts }}</span>
                        <span>Restantes: {{ entry.remainingAttempts }}</span>
                        <span>Timestamps: {{ entry.failureTimestamps.length }}</span>
                      </div>
                    </div>
                  </div>
                  <pre class="json-box">{{ pretty(stateResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: rafaga automatizada de fuerza bruta
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            En este escenario se lanzan seis intentos seguidos con la misma IP y el mismo username. La diferencia real
            se ve cuando el endpoint seguro pasa de responder con el contador a devolver <code>429</code>.
          </p>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableBurst" @click="runVulnerableBurst">
                Ejecutar rafaga vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureBurst" @click="runSecureBurst">
                Ejecutar rafaga segura
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Rafaga vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="burstVulnerableMessage" :type="burstVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ burstVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ vulnerableBurstPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ burstVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(burstVulnerableResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Rafaga segura
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="burstSecureMessage" :type="burstSecureOk ? 'success' : 'error'" outlined dense>
                    {{ burstSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ secureBurstPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ burstSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(burstSecureResult) }}</pre>
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
          <div class="mini-title">Como evitarlo a nivel de codigo</div>
          <ul class="remediation-list">
            <li>Limita intentos por IP, por usuario o por una combinacion de ambos.</li>
            <li>Devuelve <code>429 Too Many Requests</code> cuando se supera el umbral.</li>
            <li>Usa ventanas temporales, backoff o enfriamiento progresivo.</li>
            <li>Combina rate limiting con MFA, alertas y monitoreo.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave</div>
          <p class="mini-text mb-0">
            Aqui el atacante no cambia la consulta ni el objeto. Lo que explota es la capacidad de repetir muchas veces
            el mismo endpoint sensible hasta adivinar una credencial o agotar un diccionario.
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
  name: 'RateLimitLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      clientIp: '203.0.113.10',
      username: 'alice',
      password: 'wrong',
      loading: {
        vulnerable: false,
        secure: false,
        vulnerableBurst: false,
        secureBurst: false,
        state: false,
        reset: false
      },
      vulnerableResult: null,
      secureResult: null,
      burstVulnerableResult: null,
      burstSecureResult: null,
      stateResult: null,
      observedBucketsByKey: {},
      vulnerableMessage: '',
      secureMessage: '',
      burstVulnerableMessage: '',
      burstSecureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      burstVulnerableOk: false,
      burstSecureOk: false,
      presets: [
        { label: 'Credencial incorrecta', clientIp: '203.0.113.10', username: 'alice', password: 'wrong' },
        { label: 'Credencial correcta', clientIp: '203.0.113.10', username: 'alice', password: 'password123' },
        { label: 'Otra IP atacante', clientIp: '198.51.100.24', username: 'alice', password: 'wrong' }
      ],
      vulnerableCode: [
        'public RateLimitLoginResponse loginInsecure(RateLimitLoginRequest request, String clientIp) {',
        '    boolean success = isValidCredentials(request);',
        '    if (success) {',
        '        return new RateLimitLoginResponse(true, "Login correcto", 0, MAX_FAILED_ATTEMPTS);',
        '    }',
        '    return new RateLimitLoginResponse(false, "Credenciales invalidas", 0, MAX_FAILED_ATTEMPTS);',
        '}'
      ].join('\n'),
      secureCode: [
        'public RateLimitLoginResponse loginSecure(RateLimitLoginRequest request, String clientIp) {',
        '    Deque<Instant> failures = failedAttemptsByKey.computeIfAbsent(bucketKey, key -> new ArrayDeque<>());',
        '    pruneWindow(failures);',
        '    if (failures.size() >= MAX_FAILED_ATTEMPTS) {',
        '        throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos...");',
        '    }',
        '    ...',
        '}'
      ].join('\n'),
      bucketCode: [
        'private String buildKey(String clientIp, String username) {',
        '    return normalize(clientIp) + "::" + username;',
        '}',
        '',
        'private void pruneWindow(Deque<Instant> failures) {',
        '    Instant cutoff = Instant.now().minus(Duration.ofMinutes(1));',
        '    while (!failures.isEmpty() && failures.peekFirst().isBefore(cutoff)) {',
        '        failures.removeFirst();',
        '    }',
        '}'
      ].join('\n'),
      inspectCode: [
        '@GetMapping("/state")',
        'public ResponseEntity<RateLimitBucketResponse> state(@RequestParam String username, HttpServletRequest request) {',
        '    return ResponseEntity.ok(service.inspectBucket(username, clientIp(request)));',
        '}',
        '',
        '@PostMapping("/reset")',
        'public ResponseEntity<RateLimitBucketResponse> reset(@RequestParam String username, HttpServletRequest request) {',
        '    return ResponseEntity.ok(service.resetBucket(username, clientIp(request)));',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Formularios de login',
          text: 'Si el backend no limita intentos, una credencial debil puede caer por fuerza bruta o diccionario.'
        },
        {
          title: 'Recuperacion de cuentas',
          text: 'Codigos OTP o tokens cortos tambien necesitan control de frecuencia para no poder probarse en masa.'
        },
        {
          title: 'APIs de acceso con claves',
          text: 'Credential stuffing y reintentos automatizados aprovechan endpoints baratos de invocar y sin enfriamiento.'
        },
        {
          title: 'Operaciones costosas o sensibles',
          text: 'Aunque no sea login, cualquier accion repetible puede necesitar un limite temporal para evitar abuso.'
        }
      ],
      remediationPoints: [
        'Limitar intentos por IP, por usuario o por ambas dimensiones.',
        'Devolver 429 cuando se supere el umbral.',
        'Aplicar enfriamiento temporal o backoff progresivo.',
        'Combinar rate limiting con MFA, alertas y monitoreo.'
      ],
      sideBullets: [
        'La fuerza bruta depende de poder repetir rapido el mismo endpoint.',
        'Rate limiting reduce velocidad de ataque, aunque no sustituye buenas contrasenas ni MFA.'
      ]
    }
  },
  computed: {
    normalizedClientIp () {
      return this.normalizeValue(this.clientIp)
    },
    normalizedUsername () {
      return this.normalizeValue(this.username)
    },
    bucketLabel () {
      return `${this.normalizedClientIp}::${this.normalizedUsername || '(vacio)'}`
    },
    bucketEntries () {
      const username = this.normalizedUsername
      if (!username) {
        return []
      }

      return Object.values(this.observedBucketsByKey)
        .filter(entry => entry.username === username)
        .sort((left, right) => {
          if (left.clientIp === this.normalizedClientIp && right.clientIp !== this.normalizedClientIp) {
            return -1
          }

          if (right.clientIp === this.normalizedClientIp && left.clientIp !== this.normalizedClientIp) {
            return 1
          }

          return left.clientIp.localeCompare(right.clientIp)
        })
    },
    currentBucketEntry () {
      return this.bucketEntries.find(entry => entry.clientIp === this.normalizedClientIp) || null
    },
    stateSummary () {
      if (!this.stateResult || typeof this.stateResult !== 'object') {
        return this.currentBucketEntry
      }

      return {
        failedAttempts: this.currentBucketEntry ? this.currentBucketEntry.failedAttempts : this.stateResult.failedAttempts,
        remainingAttempts: this.currentBucketEntry ? this.currentBucketEntry.remainingAttempts : this.stateResult.remainingAttempts,
        limited: this.currentBucketEntry ? this.currentBucketEntry.limited : this.stateResult.limited
      }
    },
    vulnerablePreview () {
      return [
        'POST /api/lab/rate-limit/login-insecure',
        '{ "username": "alice", "password": "wrong" }',
        '',
        'No se consulta ningun contador de fallos',
        'No existe bloqueo temporal aunque fallen muchos intentos'
      ].join('\n')
    },
    securePreview () {
      return [
        'POST /api/lab/rate-limit/login-secure',
        '{ "username": "alice", "password": "wrong" }',
        '',
        'Se localiza el bucket IP::username',
        'Se poda la ventana temporal y se decide si ya toca 429'
      ].join('\n')
    },
    vulnerableDecisionPreview () {
      return [
        'validate credentials = yes',
        'count failed attempts = no',
        'temporary block = no',
        'result = the attacker can keep trying'
      ].join('\n')
    },
    secureDecisionPreview () {
      return [
        'validate credentials = yes',
        'count failed attempts = yes',
        'temporary block = yes when failures >= 5 in 60s',
        'result = the attacker is slowed down with HTTP 429'
      ].join('\n')
    },
    vulnerableRequestPreview () {
      return [
        'POST /api/lab/rate-limit/login-insecure',
        `X-Forwarded-For: ${this.clientIp}`,
        '',
        `username = ${this.username || '(vacio)'}`,
        `password = ${this.password ? '***' : '(vacio)'}`
      ].join('\n')
    },
    secureRequestPreview () {
      return [
        'POST /api/lab/rate-limit/login-secure',
        `X-Forwarded-For: ${this.clientIp}`,
        '',
        `bucket = ${this.bucketLabel}`,
        this.stateSummary ? `failedAttempts actuales = ${this.stateSummary.failedAttempts}` : 'failedAttempts actuales = (consulta pendiente)'
      ].join('\n')
    },
    vulnerableBurstPreview () {
      return [
        '6 x POST /api/lab/rate-limit/login-insecure',
        `X-Forwarded-For: ${this.clientIp}`,
        `username = ${this.username || '(vacio)'}`,
        'Esperado: no aparece 429 porque el endpoint no cuenta intentos'
      ].join('\n')
    },
    secureBurstPreview () {
      return [
        '6 x POST /api/lab/rate-limit/login-secure',
        `X-Forwarded-For: ${this.clientIp}`,
        `bucket = ${this.bucketLabel}`,
        'Esperado: tras varios fallos aparece HTTP 429 dentro de la ventana'
      ].join('\n')
    },
    vulnerableExplanation () {
      return 'La respuesta vulnerable puede fallar o acertar, pero nunca incrementa un contador util para cortar la automatizacion. El atacante conserva el mismo coste por intento.'
    },
    secureExplanation () {
      if (this.stateSummary && this.stateSummary.limited) {
        return 'El bucket ya esta limitado para esta IP y este usuario. El siguiente intento deberia caer directamente en 429 hasta que expire la ventana o se resetee en la demo.'
      }

      return 'La respuesta segura actualiza el bucket por IP y usuario. Cada fallo reduce intentos restantes hasta llegar al bloqueo temporal.'
    },
    burstVulnerableExplanation () {
      return 'En la rafaga vulnerable todos los intentos siguen entrando al mismo ritmo. Aunque fallen, el backend no introduce enfriamiento ni corte temporal.'
    },
    burstSecureExplanation () {
      return 'En la rafaga segura veras la transicion didactica: primero respuestas con contador y despues 429 cuando el bucket alcanza el umbral dentro del minuto.'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    normalizeValue (value) {
      return value == null ? '' : String(value).trim()
    },
    bucketCacheKey (username, clientIp) {
      return `${this.normalizeValue(clientIp)}::${this.normalizeValue(username)}`
    },
    normalizeBucketEntry (entry, fallbackUsername) {
      const username = this.normalizeValue(entry.username || fallbackUsername || this.username)
      const clientIp = this.normalizeValue(entry.clientIp || this.clientIp)
      const failedAttempts = Number(entry.failedAttempts || 0)
      const remainingAttempts = Number(
        entry.remainingAttempts != null
          ? entry.remainingAttempts
          : (this.stateResult && this.stateResult.maxFailedAttempts) || 5
      )

      return {
        bucketKey: entry.bucketKey || this.bucketCacheKey(username, clientIp),
        username,
        clientIp,
        failedAttempts,
        remainingAttempts,
        limited: Boolean(entry.limited),
        failureTimestamps: Array.isArray(entry.failureTimestamps) ? entry.failureTimestamps : []
      }
    },
    clearObservedBuckets (username) {
      const normalizedUsername = this.normalizeValue(username)
      if (!normalizedUsername) {
        this.observedBucketsByKey = {}
        return
      }

      const nextEntries = { ...this.observedBucketsByKey }
      Object.keys(nextEntries).forEach(key => {
        if (key.endsWith(`::${normalizedUsername}`)) {
          delete nextEntries[key]
        }
      })
      this.observedBucketsByKey = nextEntries
    },
    syncObservedBuckets (state) {
      if (!state || typeof state !== 'object') {
        return
      }

      const username = this.normalizeValue(state.username || this.username)
      if (!username) {
        return
      }

      if (Array.isArray(state.activeBuckets)) {
        this.clearObservedBuckets(username)
        if (!state.activeBuckets.length) {
          return
        }

        const nextEntries = { ...this.observedBucketsByKey }
        state.activeBuckets.forEach(entry => {
          const normalizedEntry = this.normalizeBucketEntry(entry, username)
          nextEntries[normalizedEntry.bucketKey] = normalizedEntry
        })
        this.observedBucketsByKey = nextEntries
        return
      }

      const currentEntry = this.normalizeBucketEntry({
        username,
        clientIp: state.clientIp || this.clientIp,
        failedAttempts: state.failedAttempts,
        remainingAttempts: state.remainingAttempts,
        limited: state.limited
      }, username)

      const key = currentEntry.bucketKey
      const nextEntries = { ...this.observedBucketsByKey }

      if (currentEntry.failedAttempts > 0 || currentEntry.limited) {
        nextEntries[key] = currentEntry
      } else {
        delete nextEntries[key]
      }

      this.observedBucketsByKey = nextEntries
    },
    headers () {
      return {
        'X-Forwarded-For': this.clientIp
      }
    },
    applyPreset (preset) {
      this.clientIp = preset.clientIp
      this.username = preset.username
      this.password = preset.password
    },
    async inspectState () {
      this.loading.state = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/rate-limit/state`, {
          params: { username: this.username },
          headers: this.headers()
        })
        this.stateResult = response.data
        this.syncObservedBuckets(response.data)
      } catch (error) {
        this.stateResult = apiPayload(error)
      } finally {
        this.loading.state = false
      }
    },
    async resetState () {
      this.loading.reset = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/reset`, null, {
          params: { username: this.username },
          headers: this.headers()
        })
        this.stateResult = response.data
        this.clearObservedBuckets(this.username)
        this.syncObservedBuckets(response.data)
      } catch (error) {
        this.stateResult = apiPayload(error)
      } finally {
        this.loading.reset = false
      }
    },
    async loginVulnerable () {
      this.loading.vulnerable = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-insecure`, {
          username: this.username,
          password: this.password
        }, {
          headers: this.headers()
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El endpoint vulnerable acepto el intento sin aplicar un control de frecuencia.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerable = false
      }
    },
    async loginSecure () {
      this.loading.secure = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-secure`, {
          username: this.username,
          password: this.password
        }, {
          headers: this.headers()
        })
        this.secureResult = response.data
        this.secureMessage = 'El endpoint seguro proceso el intento y actualizo el bucket de esta IP y este usuario.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        await this.inspectState()
        this.loading.secure = false
      }
    },
    async runVulnerableBurst () {
      this.loading.vulnerableBurst = true
      try {
        const attempts = []
        for (let i = 0; i < 6; i += 1) {
          try {
            const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-insecure`, {
              username: this.username,
              password: this.password
            }, {
              headers: this.headers()
            })
            attempts.push({ attempt: i + 1, status: response.status, body: response.data })
          } catch (error) {
            attempts.push({ attempt: i + 1, status: error.response ? error.response.status : 'ERR', body: apiPayload(error) })
          }
        }
        this.burstVulnerableResult = attempts
        this.burstVulnerableMessage = 'La rafaga vulnerable muestra que no aparece ningun corte temporal aunque fallen muchos intentos.'
        this.burstVulnerableOk = true
      } catch (error) {
        this.burstVulnerableResult = apiPayload(error)
        this.burstVulnerableMessage = apiMessage(error)
        this.burstVulnerableOk = false
      } finally {
        this.loading.vulnerableBurst = false
      }
    },
    async runSecureBurst () {
      this.loading.secureBurst = true
      try {
        const attempts = []
        for (let i = 0; i < 6; i += 1) {
          try {
            const response = await this.$http.post(`${this.apiBaseUrl}/lab/rate-limit/login-secure`, {
              username: this.username,
              password: this.password
            }, {
              headers: this.headers()
            })
            attempts.push({ attempt: i + 1, status: response.status, body: response.data })
          } catch (error) {
            attempts.push({ attempt: i + 1, status: error.response ? error.response.status : 'ERR', body: apiPayload(error) })
          }
        }
        this.burstSecureResult = attempts
        this.burstSecureMessage = 'La rafaga segura permite ver cuando el backend pasa de contar fallos a responder con 429.'
        this.burstSecureOk = true
      } catch (error) {
        this.burstSecureResult = apiPayload(error)
        this.burstSecureMessage = apiMessage(error)
        this.burstSecureOk = false
      } finally {
        await this.inspectState()
        this.loading.secureBurst = false
      }
    }
  },
  mounted () {
    this.inspectState()
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

.payload-actions,
.bucket-strip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.bucket-strip__text {
  color: #4b5563;
  font-size: 0.95rem;
}

.bucket-overview {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 16px;
}

.bucket-overview__item,
.bucket-entry {
  border: 1px solid #dbe4f0;
  border-radius: 10px;
  padding: 12px;
  background: #f8fafc;
}

.bucket-overview__label,
.bucket-entry__meta {
  display: block;
  color: #64748b;
  font-size: 0.82rem;
  margin-bottom: 4px;
}

.bucket-entry-list {
  display: grid;
  gap: 10px;
  margin-top: 8px;
}

.bucket-entry__header,
.bucket-entry__stats {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
}

.bucket-entry__header {
  margin-bottom: 6px;
  color: #0f172a;
}

.bucket-entry__stats {
  color: #334155;
  font-size: 0.9rem;
}

.bucket-entry--current {
  border-color: #2563eb;
  background: #eff6ff;
}

.bucket-entry--limited {
  border-color: #c62828;
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

  .bucket-overview {
    grid-template-columns: 1fr;
  }

  .didactic-stack {
    min-height: 0;
  }
}
</style>
