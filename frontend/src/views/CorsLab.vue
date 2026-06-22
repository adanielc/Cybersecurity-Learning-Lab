<template>
  <lab-page-shell
    title="CORS"
    icon="mdi-origin"
    description="CORS no protege la API por sí solo, pero una política demasiado permisiva puede permitir que un sitio externo lea respuestas desde el navegador del usuario. Aquí se compara una política abierta con una restrictiva."
    vulnerable-endpoint="GET /api/lab/cors/public-data | GET /api/lab/cors/private-data"
    secure-endpoint="GET /api/lab/cors/secure-private-data"
    vulnerable-method="GET"
    secure-method="GET"
    vulnerable-hint="La política vulnerable permite muchos orígenes, métodos y cabeceras."
    secure-hint="La política segura solo permite el origen legítimo del frontend y reduce superficie."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="CORS es una decisión del navegador sobre si JavaScript de un origen puede leer una respuesta de otro origen. Si la API responde con una política demasiado amplia, un sitio ajeno puede terminar leyendo datos que no debía."
    owasp-label="OWASP API8:2023 Security Misconfiguration"
    risk-label="Impacto medio/alto: lectura cruzada no prevista desde navegadores"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué pasa por detrás</div>
          <p class="mini-text">
            El navegador envía una petición con un origen implícito. Si la respuesta incluye cabeceras CORS demasiado
            abiertas, JavaScript de un sitio externo puede leer el contenido y usarlo dentro de ese sitio atacante.
          </p>
        </div>

        <div>
          <div class="mini-title">Política permisiva</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decisión del navegador</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>Un origen externo puede leer respuestas educativas que no estaban pensadas para él.</li>
            <li>El problema aumenta si además hay credenciales o datos sensibles.</li>
            <li>CORS abierto no reemplaza autenticación, pero sí amplía quién puede leer desde el navegador.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué cambia</div>
          <p class="mini-text">
            La política segura limita el origen permitido al frontend legítimo. Aunque el endpoint exista, un sitio con
            otro origen no recibe permiso del navegador para leer la respuesta con JavaScript.
          </p>
        </div>

        <div>
          <div class="mini-title">Política restringida</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decisión del navegador</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>El frontend legítimo puede leer la respuesta.</li>
            <li>Un origen atacante no recibe permiso de lectura cruzada.</li>
            <li>La política sigue siendo complementaria a autenticación y autorización reales.</li>
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
            <div class="flow-block__title">Escenario 1: política CORS permisiva</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableCorsCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureCorsCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: endpoints didácticos</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Respuesta vulnerable</div>
                <pre class="code-box">{{ vulnerableEndpointCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Respuesta segura</div>
                <pre class="code-box">{{ secureEndpointCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: origen atacante contra política permisiva
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            El navegador no deja cambiar manualmente la cabecera <code>Origin</code> desde JavaScript, así que esta parte
            de la vista simula qué ocurriría si la petición viniera de otro sitio como <code>https://evil.example</code>.
            El backend responde igual; lo que cambia es si el navegador permite a ese origen leer la respuesta.
          </p>

          <v-row>
            <v-col cols="12" md="6">
              <v-text-field
                :value="browserOrigin"
                label="Origen actual del laboratorio"
                outlined
                dense
                readonly
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="originHint"
                label="Origen atacante simulado"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="item in originPresets"
              :key="item.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="originHint = item.origin"
            >
              {{ item.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.publicData" @click="loadPublicData">
                Leer pública vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="warning" outlined :loading="loading.privateData" @click="loadPrivateData">
                Leer privada vulnerable
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
                  Qué leería el navegador
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
                  <div class="explanation-box explanation-box--danger mt-4">
                    Esta evaluación es didáctica: la petición real sale desde el origen del laboratorio, pero muestra lo
                    que pasaría si el mismo endpoint respondiera a un origen externo con esta política CORS abierta.
                  </div>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: mismo origen atacante contra política restrictiva
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Ahora el endpoint seguro responde con una política pensada solo para el origen legítimo del frontend. Si el
            origen simulado no coincide, el navegador debería bloquear la lectura cruzada aunque el endpoint exista.
          </p>

          <pre class="sql-box sql-box--safe mb-4">{{ secureRequestPreview }}</pre>

          <v-row>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.securePrivateData" @click="loadSecurePrivateData">
                Leer privada segura
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
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

                  <div class="explanation-box explanation-box--safe">
                    {{ secureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(secureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Qué decidiría el navegador
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
                  <div class="explanation-box explanation-box--safe mt-4">
                    Aquí se ve la diferencia real de CORS: el backend puede responder, pero solo el origen autorizado
                    recibe permiso del navegador para leer el contenido con JavaScript.
                  </div>
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
          <div class="mini-title">Cómo evitarlo a nivel de configuración</div>
          <ul class="remediation-list">
            <li>Permite solo los orígenes legítimos del frontend.</li>
            <li>Limita métodos y cabeceras a lo estrictamente necesario.</li>
            <li>No mezcles <code>origins</code> amplios con endpoints que devuelven datos sensibles.</li>
            <li>Recuerda que CORS no sustituye autenticación ni autorización.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave</div>
          <p class="mini-text mb-0">
            En SQLi o NoSQLi el atacante altera la consulta. En CORS el problema está en qué orígenes pueden leer la
            respuesta desde el navegador, aunque la API siga siendo la misma.
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
  name: 'CorsLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      browserOrigin: window.location.origin,
      originHint: 'https://evil.example',
      secureAllowedOrigins: [window.location.origin],
      loading: {
        publicData: false,
        privateData: false,
        securePrivateData: false
      },
      vulnerableResult: null,
      secureResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      vulnerableOk: false,
      secureOk: false,
      lastVulnerableEndpoint: '/api/lab/cors/private-data',
      originPresets: [
        { label: 'evil.example', origin: 'https://evil.example' },
        { label: 'frontend legítimo', origin: window.location.origin },
        { label: 'partner.example', origin: 'https://partner.example' }
      ],
      vulnerableCorsCode: [
        'private CorsConfiguration insecureCorsConfiguration() {',
        '    CorsConfiguration configuration = new CorsConfiguration();',
        '    configuration.setAllowedOriginPatterns(List.of("*"));',
        '    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));',
        '    configuration.setAllowedHeaders(List.of("*"));',
        '    configuration.setAllowCredentials(false);',
        '    return configuration;',
        '}'
      ].join('\n'),
      secureCorsCode: [
        'private CorsConfiguration secureCorsConfiguration(LabSecurityProperties properties) {',
        '    CorsConfiguration configuration = new CorsConfiguration();',
        '    configuration.setAllowedOrigins(properties.cors().allowedOrigins());',
        '    configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));',
        '    configuration.setAllowedHeaders(List.of("Content-Type", "Authorization", ...));',
        '    configuration.setAllowCredentials(true);',
        '    return configuration;',
        '}'
      ].join('\n'),
      vulnerableEndpointCode: [
        '@GetMapping("/private-data")',
        'public ResponseEntity<CorsLabResponseDto> privateData() {',
        '    return ResponseEntity.ok(buildResponse(',
        '        "/api/lab/cors/private-data",',
        '        "Dato privado educativo...",',
        '        "Resumen interno del laboratorio...",',
        '        INSECURE',
        '    ));',
        '}'
      ].join('\n'),
      secureEndpointCode: [
        '@GetMapping("/secure-private-data")',
        'public ResponseEntity<CorsLabResponseDto> securePrivateData() {',
        '    return ResponseEntity.ok(buildResponse(',
        '        "/api/lab/cors/secure-private-data",',
        '        "Mismo dato privado...",',
        '        "Acceso pensado solo para el frontend autorizado.",',
        '        SECURE',
        '    ));',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Paneles administrativos',
          text: 'Si un endpoint devuelve datos internos y permite muchos orígenes, otra web podría leer respuestas desde el navegador del usuario.'
        },
        {
          title: 'APIs con frontend separado',
          text: 'Arquitecturas SPA + API suelen necesitar CORS, y ahí aparecen configuraciones demasiado amplias por comodidad.'
        },
        {
          title: 'Entornos con cookies o tokens',
          text: 'El riesgo crece cuando la API acepta credenciales y además expone respuestas a orígenes no previstos.'
        },
        {
          title: 'Integraciones improvisadas',
          text: 'Permitir * o demasiados headers/métodos suele ser una forma rápida de “hacer que funcione” a costa de abrir superficie.'
        }
      ],
      remediationPoints: [
        'Permitir solo el origen legítimo del frontend.',
        'Limitar métodos y cabeceras a lo estrictamente necesario.',
        'No mezclar políticas amplias con datos sensibles.',
        'Recordar que CORS no sustituye autenticación ni autorización.'
      ],
      sideBullets: [
        'CORS abierto no es lo mismo que API pública, pero sí facilita lectura cruzada desde navegadores.',
        'Una política CORS correcta sigue necesitando controles de acceso reales.'
      ]
    }
  },
  computed: {
    normalizedOriginHint () {
      return String(this.originHint || '').trim() || '(vacío)'
    },
    insecureReadAllowed () {
      return true
    },
    secureReadAllowed () {
      return this.secureAllowedOrigins.includes(this.normalizedOriginHint)
    },
    vulnerableRequestPreview () {
      return [
        `GET ${this.lastVulnerableEndpoint}`,
        '',
        `Origin simulado: ${this.normalizedOriginHint}`,
        'Respuesta CORS esperada: Access-Control-Allow-Origin: * o patrón amplio'
      ].join('\n')
    },
    secureRequestPreview () {
      return [
        'GET /api/lab/cors/secure-private-data',
        '',
        `Origin simulado: ${this.normalizedOriginHint}`,
        `Origen permitido por la política segura: ${this.secureAllowedOrigins.join(', ')}`
      ].join('\n')
    },
    vulnerablePreview () {
      return [
        'Access-Control-Allow-Origin: *',
        'Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers: *',
        'El navegador externo recibe permiso amplio de lectura'
      ].join('\n')
    },
    securePreview () {
      return [
        `Access-Control-Allow-Origin: ${this.secureAllowedOrigins.join(', ')}`,
        'Access-Control-Allow-Methods: GET, POST, OPTIONS',
        'Access-Control-Allow-Headers: Content-Type, Authorization, ...',
        'Solo el frontend legítimo debería leer desde navegador'
      ].join('\n')
    },
    vulnerableDecisionPreview () {
      return [
        `origin = ${this.normalizedOriginHint}`,
        'policy = broad / wildcard',
        `browser allows read = ${String(this.insecureReadAllowed)}`,
        'JavaScript del sitio externo puede procesar la respuesta'
      ].join('\n')
    },
    secureDecisionPreview () {
      return [
        `origin = ${this.normalizedOriginHint}`,
        `allowedOrigins = ${this.secureAllowedOrigins.join(', ')}`,
        `browser allows read = ${String(this.secureReadAllowed)}`,
        this.secureReadAllowed ? 'El origen coincide y el navegador deja leer' : 'El origen no coincide y el navegador bloquea la lectura cruzada'
      ].join('\n')
    },
    vulnerableExplanation () {
      return this.lastVulnerableEndpoint === '/api/lab/cors/public-data'
        ? 'En datos públicos el impacto es menor, pero la política sigue siendo amplia. Sirve para ver que CORS permisivo no distingue sensibilidad por sí mismo.'
        : 'Aquí está el caso didáctico importante: el dato es privado a nivel educativo, pero la política permisiva permitiría que otro origen lo leyera desde el navegador.'
    },
    secureExplanation () {
      return this.secureReadAllowed
        ? 'Como el origen simulado coincide con el frontend legítimo, la política segura permitiría la lectura. El punto es que no la concedería a orígenes distintos.'
        : 'Como el origen simulado no está en la allowlist, el navegador debería bloquear la lectura cruzada aunque el endpoint exista y responda.'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    async loadPublicData () {
      this.loading.publicData = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/cors/public-data`)
        this.vulnerableResult = response.data
        this.lastVulnerableEndpoint = '/api/lab/cors/public-data'
        this.vulnerableMessage = 'El endpoint devolvió datos públicos con una política CORS permisiva.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.publicData = false
      }
    },
    async loadPrivateData () {
      this.loading.privateData = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/cors/private-data`)
        this.vulnerableResult = response.data
        this.lastVulnerableEndpoint = '/api/lab/cors/private-data'
        this.vulnerableMessage = 'El endpoint devolvió el dato privado educativo bajo una política CORS abierta.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.privateData = false
      }
    },
    async loadSecurePrivateData () {
      this.loading.securePrivateData = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/cors/secure-private-data`)
        this.secureResult = response.data
        this.secureMessage = 'El endpoint seguro devolvió el dato bajo una política CORS restrictiva.'
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.securePrivateData = false
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
