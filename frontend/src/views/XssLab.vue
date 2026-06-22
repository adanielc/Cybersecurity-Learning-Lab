<template>
  <lab-page-shell
    title="Cross-Site Scripting"
    icon="mdi-code-tags"
    description="XSS aparece cuando la aplicacion trata contenido controlado por el usuario como si fuera HTML confiable. Aqui se compara el almacenamiento y renderizado directo de comentarios con una salida segura que neutraliza el payload."
    vulnerable-endpoint="POST /api/lab/xss/comments | GET /api/lab/xss/comments"
    secure-endpoint="POST /api/lab/xss/comments-secure | GET /api/lab/xss/comments-secure"
    vulnerable-method="POST / GET"
    secure-method="POST / GET"
    vulnerable-hint="La version vulnerable persiste el payload y lo renderiza con HTML activo en la vista."
    secure-hint="La version segura devuelve el contenido escapado y lo muestra como texto, no como HTML interpretable."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="El fallo no esta solo en guardar un comentario con etiquetas. El fallo real aparece cuando ese contenido vuelve al navegador y la UI lo interpreta como HTML o JavaScript confiable."
    owasp-label="OWASP A03:2021 Injection / Stored XSS"
    risk-label="Impacto alto: ejecucion de JavaScript en navegador y robo de sesion o acciones en nombre del usuario"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que pasa por detras</div>
          <p class="mini-text">
            El usuario envia un comentario con HTML o eventos inline. El backend vulnerable lo guarda tal cual y la UI
            lo inyecta con <code>v-html</code>. En ese momento el navegador interpreta el payload como contenido activo.
          </p>
        </div>

        <div>
          <div class="mini-title">Flujo vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decision del navegador</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>El payload queda almacenado y puede afectar a quien cargue la lista despues.</li>
            <li>No hace falta inyeccion SQL ni cambiar IDs: basta con que la UI interprete HTML de usuario.</li>
            <li>El riesgo real aparece cuando hay eventos inline, scripts o HTML peligroso.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que cambia</div>
          <p class="mini-text">
            La version segura sigue almacenando el texto del usuario, pero antes de devolverlo neutraliza caracteres
            peligrosos. El frontend lo muestra como texto normal en vez de tratarlo como HTML ejecutable.
          </p>
        </div>

        <div>
          <div class="mini-title">Flujo seguro</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decision del navegador</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>El comentario sigue siendo visible para el usuario.</li>
            <li>Las etiquetas salen escapadas y no se convierten en nodos HTML activos.</li>
            <li>La salida deja de ser un vector de ejecucion dentro del navegador.</li>
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
          Codigo del backend y del renderizado
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: almacenar el comentario</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableStoreCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureStoreCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: renderizar la lista</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Render vulnerable</div>
                <pre class="code-box">{{ vulnerableRenderCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Render seguro</div>
                <pre class="code-box">{{ secureRenderCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: POST que almacena el payload
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aqui se publica un comentario controlado por el usuario. El punto didactico es que el problema de XSS no se
            consuma aun; primero el payload queda persistido y listo para ejecutarse cuando otra vista lo renderice mal.
          </p>

          <v-row>
            <v-col cols="12" md="4">
              <v-text-field
                v-model="author"
                label="Autor"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="8">
              <v-text-field
                v-model="content"
                label="Payload"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="payload in payloadPresets"
              :key="payload.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="applyPayload(payload)"
            >
              {{ payload.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerablePost" @click="postVulnerable">
                Ejecutar POST vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.securePost" @click="postSecure">
                Ejecutar POST seguro
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Respuesta vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="postVulnerableMessage" :type="postVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ postVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ vulnerablePostPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ postVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(postVulnerableResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Respuesta segura
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="postSecureMessage" :type="postSecureOk ? 'success' : 'error'" outlined dense>
                    {{ postSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ securePostPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ postSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(postSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: GET que renderiza el contenido almacenado
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Este es el momento en que un stored XSS se materializa. La misma coleccion se carga de dos maneras: una la
            interpreta como HTML activo y la otra la presenta como texto neutralizado.
          </p>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableGet" @click="getVulnerable">
                Ejecutar GET vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureGet" @click="getSecure">
                Ejecutar GET seguro
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Lista vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="getVulnerableMessage" :type="getVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ getVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ vulnerableGetPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ getVulnerableExplanation }}
                  </div>

                  <div class="preview-panel preview-panel--danger mt-4">
                    <div class="preview-panel__title">Render con <code>v-html</code></div>
                    <div v-if="Array.isArray(vulnerableComments) && vulnerableComments.length">
                      <div v-for="comment in vulnerableComments" :key="comment.id" class="comment-card">
                        <div class="comment-meta">{{ comment.author }} - {{ comment.createdAt }}</div>
                        <div v-html="comment.content" />
                      </div>
                    </div>
                    <div v-else class="preview-empty">Carga la lista vulnerable para ver el renderizado.</div>
                  </div>

                  <pre class="json-box mt-4">{{ pretty(vulnerableComments) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Lista segura
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="getSecureMessage" :type="getSecureOk ? 'success' : 'error'" outlined dense>
                    {{ getSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ secureGetPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ getSecureExplanation }}
                  </div>

                  <div class="preview-panel preview-panel--safe mt-4">
                    <div class="preview-panel__title">Render como texto</div>
                    <div v-if="Array.isArray(secureComments) && secureComments.length">
                      <div v-for="comment in secureComments" :key="comment.id" class="comment-card">
                        <div class="comment-meta">{{ comment.author }} - {{ comment.createdAt }}</div>
                        <div>{{ comment.content }}</div>
                      </div>
                    </div>
                    <div v-else class="preview-empty">Carga la lista segura para ver el renderizado.</div>
                  </div>

                  <pre class="json-box mt-4">{{ pretty(secureComments) }}</pre>
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
            <li>Evita <code>v-html</code> o cualquier renderizado HTML con contenido del usuario.</li>
            <li>Escapa o sanitiza el contenido antes de devolverlo o antes de pintarlo.</li>
            <li>Aplica CSP como defensa en profundidad, no como unica mitigacion.</li>
            <li>Revisa tambien plantillas de correo, markdown enriquecido y paneles de administracion.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave</div>
          <p class="mini-text mb-0">
            En XSS el atacante no busca cambiar la consulta del backend. Busca que el navegador del usuario ejecute o
            interprete como activo un contenido que debia tratarse como texto no confiable.
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
  name: 'XssLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      author: 'alice',
      content: '<strong>HTML visible en modo vulnerable</strong>',
      loading: {
        vulnerablePost: false,
        vulnerableGet: false,
        securePost: false,
        secureGet: false
      },
      postVulnerableResult: null,
      postSecureResult: null,
      vulnerableComments: null,
      secureComments: null,
      postVulnerableMessage: '',
      postSecureMessage: '',
      getVulnerableMessage: '',
      getSecureMessage: '',
      postVulnerableOk: false,
      postSecureOk: false,
      getVulnerableOk: false,
      getSecureOk: false,
      payloadPresets: [
        { label: 'HTML visible', author: 'alice', content: '<strong>HTML visible en modo vulnerable</strong>' },
        { label: 'Imagen con onerror', author: 'attacker', content: "<img src=x onerror=alert('XSS laboratorio')>" },
        { label: 'Enlace malicioso', author: 'attacker', content: "<a href=\"javascript:alert('XSS')\">Haz clic</a>" }
      ],
      vulnerableStoreCode: [
        'public CommentDto createVulnerable(CommentCreateRequest request) {',
        '    CommentDto comment = createAndStore(request, false);',
        '    return comment;',
        '}',
        '',
        '@PostMapping("/comments")',
        'public ResponseEntity<CommentDto> createVulnerable(...) {',
        '    return ResponseEntity.ok(service.createVulnerable(request));',
        '}'
      ].join('\n'),
      secureStoreCode: [
        'public CommentDto createSecure(CommentCreateRequest request) {',
        '    CommentDto comment = createAndStore(request, false);',
        '    return new CommentDto(comment.id(), comment.author(), HtmlUtils.htmlEscape(comment.content()), comment.createdAt());',
        '}',
        '',
        '@PostMapping("/comments-secure")',
        'public ResponseEntity<CommentDto> createSecure(...) {',
        '    return ResponseEntity.ok(service.createSecure(request));',
        '}'
      ].join('\n'),
      vulnerableRenderCode: [
        '<div v-for="comment in vulnerableComments" :key="comment.id">',
        '  <div v-html="comment.content" />',
        '</div>',
        '',
        'GET /api/lab/xss/comments -> contenido tal cual'
      ].join('\n'),
      secureRenderCode: [
        '<div v-for="comment in secureComments" :key="comment.id">',
        '  <div>{{ comment.content }}</div>',
        '</div>',
        '',
        'GET /api/lab/xss/comments-secure -> contenido escapado'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Comentarios y foros',
          text: 'Contenido enriquecido o texto libre puede convertirse en HTML activo si la vista lo interpreta como confiable.'
        },
        {
          title: 'Campos de perfil y bios',
          text: 'Nombres visibles, firmas o descripciones persistidas pueden convertirse en stored XSS si luego se renderizan mal.'
        },
        {
          title: 'Paneles internos',
          text: 'Herramientas de soporte o moderacion suelen mostrar contenido de usuario y pueden ejecutar payloads persistidos.'
        },
        {
          title: 'Previews enriquecidos',
          text: 'Markdown, WYSIWYG o plantillas HTML requieren sanitizacion estricta antes de mostrarse en navegador.'
        }
      ],
      remediationPoints: [
        'Escapar o sanitizar contenido antes de renderizar.',
        'Evitar v-html con contenido de usuario.',
        'Aplicar CSP como defensa en profundidad.',
        'Revisar tanto almacenado como renderizado, no solo la escritura.'
      ],
      sideBullets: [
        'Stored XSS: el payload se guarda y afecta a usuarios posteriores.',
        'Reflected XSS: el payload vuelve en la misma respuesta sin persistirse.'
      ]
    }
  },
  computed: {
    vulnerablePreview () {
      return [
        'POST /api/lab/xss/comments',
        'content = payload controlado por usuario',
        'store = contenido tal cual',
        'GET /comments + v-html = HTML activo dentro del navegador'
      ].join('\n')
    },
    securePreview () {
      return [
        'POST /api/lab/xss/comments-secure',
        'content = payload controlado por usuario',
        'response/list = HtmlUtils.htmlEscape(...)',
        'render = texto visible, no HTML interpretable'
      ].join('\n')
    },
    vulnerableDecisionPreview () {
      return [
        'backend output = raw comment content',
        'frontend render = v-html',
        'browser interpretation = HTML / inline events',
        'result = the payload can execute or alter the DOM'
      ].join('\n')
    },
    secureDecisionPreview () {
      return [
        'backend output = escaped content',
        'frontend render = text interpolation',
        'browser interpretation = plain text',
        'result = the payload loses execution capability'
      ].join('\n')
    },
    vulnerablePostPreview () {
      return [
        'POST /api/lab/xss/comments',
        '',
        `author = ${this.author || '(vacio)'}`,
        `content = ${this.content || '(vacio)'}`
      ].join('\n')
    },
    securePostPreview () {
      return [
        'POST /api/lab/xss/comments-secure',
        '',
        `author = ${this.author || '(vacio)'}`,
        'La respuesta devuelve content escapado'
      ].join('\n')
    },
    vulnerableGetPreview () {
      return [
        'GET /api/lab/xss/comments',
        '',
        'La lista devuelve content sin escape',
        'La UI vulnerable lo inserta con v-html'
      ].join('\n')
    },
    secureGetPreview () {
      return [
        'GET /api/lab/xss/comments-secure',
        '',
        'La lista devuelve content escapado',
        'La UI segura lo muestra como texto'
      ].join('\n')
    },
    postVulnerableExplanation () {
      return 'El payload ya quedo persistido en la coleccion vulnerable. Aunque aun no se haya renderizado, el comentario esta listo para ejecutarse cuando otra vista lo trate como HTML.'
    },
    postSecureExplanation () {
      return 'La respuesta segura ya devuelve el contenido neutralizado. El comentario sigue existiendo, pero la API evita que salga como HTML activo en la vista segura.'
    },
    getVulnerableExplanation () {
      return 'Aqui es donde el stored XSS se consuma: el frontend vulnerable usa v-html y delega en el navegador la interpretacion del contenido controlado por el atacante.'
    },
    getSecureExplanation () {
      return 'La lista segura mantiene el mismo contenido funcional para el usuario, pero lo presenta como texto. Las etiquetas se ven, no se ejecutan.'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    applyPayload (payload) {
      this.author = payload.author
      this.content = payload.content
    },
    async postVulnerable () {
      this.loading.vulnerablePost = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/xss/comments`, {
          author: this.author,
          content: this.content
        })
        this.postVulnerableResult = response.data
        this.postVulnerableMessage = 'El comentario vulnerable se almaceno con el payload intacto.'
        this.postVulnerableOk = true
      } catch (error) {
        this.postVulnerableResult = apiPayload(error)
        this.postVulnerableMessage = apiMessage(error)
        this.postVulnerableOk = false
      } finally {
        this.loading.vulnerablePost = false
      }
    },
    async postSecure () {
      this.loading.securePost = true
      try {
        const response = await this.$http.post(`${this.apiBaseUrl}/lab/xss/comments-secure`, {
          author: this.author,
          content: this.content
        })
        this.postSecureResult = response.data
        this.postSecureMessage = 'La respuesta segura devolvio el contenido neutralizado.'
        this.postSecureOk = true
      } catch (error) {
        this.postSecureResult = apiPayload(error)
        this.postSecureMessage = apiMessage(error)
        this.postSecureOk = false
      } finally {
        this.loading.securePost = false
      }
    },
    async getVulnerable () {
      this.loading.vulnerableGet = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/xss/comments`)
        this.vulnerableComments = response.data
        this.getVulnerableMessage = 'La lista vulnerable devolvio contenido listo para interpretarse como HTML.'
        this.getVulnerableOk = true
      } catch (error) {
        this.vulnerableComments = apiPayload(error)
        this.getVulnerableMessage = apiMessage(error)
        this.getVulnerableOk = false
      } finally {
        this.loading.vulnerableGet = false
      }
    },
    async getSecure () {
      this.loading.secureGet = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/xss/comments-secure`)
        this.secureComments = response.data
        this.getSecureMessage = 'La lista segura devolvio contenido neutralizado para mostrarse como texto.'
        this.getSecureOk = true
      } catch (error) {
        this.secureComments = apiPayload(error)
        this.getSecureMessage = apiMessage(error)
        this.getSecureOk = false
      } finally {
        this.loading.secureGet = false
      }
    }
  },
  mounted () {
    this.getSecure()
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

.preview-panel {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 14px;
  background: #fafafa;
}

.preview-panel--danger {
  border-color: rgba(198, 40, 40, 0.22);
  background: #fffafa;
}

.preview-panel--safe {
  border-color: rgba(46, 125, 50, 0.22);
  background: #f7fff9;
}

.preview-panel__title {
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 10px;
}

.preview-empty {
  color: #6b7280;
}

.comment-card {
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  padding: 12px;
  margin-bottom: 12px;
  background: #ffffff;
}

.comment-card:last-child {
  margin-bottom: 0;
}

.comment-meta {
  font-size: 0.8rem;
  color: #64748b;
  margin-bottom: 6px;
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
