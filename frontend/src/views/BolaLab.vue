<template>
  <lab-page-shell
    title="BOLA / IDOR"
    icon="mdi-account-key"
    description="Broken Object Level Authorization aparece cuando el backend usa un identificador de objeto como si fuera una autorización. Aquí se compara el acceso directo por ID con la validación real de ownership y rol."
    vulnerable-endpoint="GET /api/lab/bola/profile/{userId}"
    secure-endpoint="GET /api/lab/bola/profile-secure/{userId} | GET /api/lab/bola/my-profile"
    vulnerable-method="GET"
    secure-method="GET"
    vulnerable-hint="La versión vulnerable devuelve el objeto pedido solo porque el ID existe."
    secure-hint="La versión segura compara el recurso solicitado con la identidad educativa y devuelve 403 cuando no corresponde."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="El error no está en poner un ID en la URL. El error está en confiar en ese ID como única decisión de autorización, sin comprobar si el usuario autenticado puede acceder a ese objeto."
    owasp-label="OWASP API1:2023 Broken Object Level Authorization"
    risk-label="Impacto alto: acceso horizontal no autorizado y fuga de datos personales"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué pasa por detrás</div>
          <p class="mini-text">
            El atacante no necesita inyectar código. Solo cambia el identificador del recurso en la URL y prueba si el
            backend devuelve el objeto sin verificar ownership.
          </p>
        </div>

        <div>
          <div class="mini-title">GET vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableRequestPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decisión del backend</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>Un usuario normal puede leer el perfil de otro cambiando el <code>userId</code>.</li>
            <li>La URL se convierte en un enumerador de objetos accesibles.</li>
            <li>El fallo es de autorización a nivel de objeto, no de autenticación.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Qué cambia</div>
          <p class="mini-text">
            En la versión segura el backend usa la identidad educativa enviada en las cabeceras <code>X-Lab-*</code> para
            comprobar si el objeto pedido pertenece al usuario o si su rol puede acceder.
          </p>
        </div>

        <div>
          <div class="mini-title">GET seguro</div>
          <pre class="sql-box sql-box--safe">{{ secureRequestPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decisión del backend</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>El propietario puede acceder a su recurso.</li>
            <li>Un administrador puede acceder por privilegio explícito.</li>
            <li>Un usuario sin permisos recibe <code>403 Forbidden</code>.</li>
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
          Usuarios del laboratorio
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="user-grid">
            <div v-for="user in sampleUsers" :key="user.id" class="user-item">
              <div class="user-item__id">ID {{ user.id }}</div>
              <div class="user-item__name">{{ user.username }}</div>
              <div class="user-item__meta">{{ user.role }} · {{ user.fullName }}</div>
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
            <div class="flow-block__title">Escenario 1: acceso directo a un perfil por ID</div>
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
            <div class="flow-block__title">Escenario 2: obtener el propio perfil autenticado</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Endpoint previsto</div>
                <pre class="code-box">{{ myProfileCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption">Idea didáctica</div>
                <pre class="code-box">{{ identityFlowCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: GET de perfil ajeno por ID
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aquí el ataque consiste en cambiar el <code>userId</code> objetivo manteniendo una identidad autenticada de
            menor privilegio. Si el backend responde solo por el ID de la URL, existe BOLA / IDOR.
          </p>

          <v-row>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="myUserId"
                label="Mi userId educativo"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="myUsername"
                label="Mi username educativo"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="3">
              <v-select
                v-model="myRole"
                :items="roles"
                label="Mi rol educativo"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
            <v-col cols="12" md="3">
              <v-text-field
                v-model="targetUserId"
                label="userId objetivo"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="item in presets"
              :key="item.label"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="applyPreset(item)"
            >
              {{ item.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerable" @click="loadVulnerableProfile">
                Ejecutar GET vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secure" @click="loadSecureProfile">
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
          Escenario 2: GET de mi propio perfil
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Este es el caso de uso legítimo. El cliente no pide un ID ajeno, sino que el backend resuelve el perfil a
            partir de la identidad autenticada enviada en las cabeceras educativas.
          </p>

          <div class="payload-actions mb-2">
            <v-btn small outlined color="primary" @click="applyMinePreset">
              Cargar preset propietario
            </v-btn>
          </div>

          <pre class="sql-box sql-box--safe mb-4">{{ myProfileRequestPreview }}</pre>

          <v-row>
            <v-col cols="12" md="6">
              <v-btn block color="primary" :loading="loading.mine" @click="loadMyProfile">
                Ejecutar GET /my-profile
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Respuesta del backend
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="myProfileMessage" :type="myProfileOk ? 'success' : 'error'" outlined dense>
                    {{ myProfileMessage }}
                  </v-alert>

                  <div class="explanation-box explanation-box--safe">
                    {{ myProfileExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(myProfileResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Qué demuestra
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--safe">{{ myProfileDecisionPreview }}</pre>
                  <div class="explanation-box explanation-box--safe mt-4">
                    El endpoint pensado para el caso legítimo no necesita confiar en un <code>userId</code> arbitrario de
                    la URL. Resuelve el recurso desde la identidad autenticada y reduce superficie de abuso.
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
          <div class="mini-title">Cómo evitarlo a nivel de código</div>
          <ul class="remediation-list">
            <li>Compara siempre el objeto solicitado con la identidad autenticada en el backend.</li>
            <li>No uses el identificador de la URL como autorización implícita.</li>
            <li>Separa acceso por ownership y acceso por rol administrativo.</li>
            <li>Expón solo DTOs públicos y evita devolver datos innecesarios aunque el acceso sea legítimo.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave para el alumno</div>
          <p class="mini-text mb-0">
            En SQLi y NoSQLi el atacante intenta alterar una consulta. En BOLA / IDOR el atacante prueba si puede leer
            o modificar objetos ajenos cambiando solo un identificador válido.
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
  name: 'BolaLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      myUserId: '2',
      myUsername: 'alice',
      myRole: 'USER',
      targetUserId: '1',
      roles: ['USER', 'ADMIN'],
      sampleUsers: [
        { id: '1', username: 'admin', role: 'ADMIN', fullName: 'System Administrator' },
        { id: '2', username: 'alice', role: 'USER', fullName: 'Alice Carter' },
        { id: '3', username: 'bob', role: 'USER', fullName: 'Bob Stone' },
        { id: '4', username: 'auditor', role: 'ADMIN', fullName: 'Audit User' }
      ],
      presets: [
        {
          label: 'alice -> admin',
          userId: '2',
          username: 'alice',
          role: 'USER',
          targetUserId: '1'
        },
        {
          label: 'alice -> alice',
          userId: '2',
          username: 'alice',
          role: 'USER',
          targetUserId: '2'
        },
        {
          label: 'bob -> alice',
          userId: '3',
          username: 'bob',
          role: 'USER',
          targetUserId: '2'
        },
        {
          label: 'admin -> bob',
          userId: '1',
          username: 'admin',
          role: 'ADMIN',
          targetUserId: '3'
        }
      ],
      loading: {
        vulnerable: false,
        secure: false,
        mine: false
      },
      vulnerableResult: null,
      secureResult: null,
      myProfileResult: null,
      vulnerableMessage: '',
      secureMessage: '',
      myProfileMessage: '',
      vulnerableOk: false,
      secureOk: false,
      myProfileOk: false,
      vulnerableCode: [
        'public UserProfileDto getProfileVulnerable(Long userId) {',
        '    return findProfileOrThrow(userId);',
        '}'
      ].join('\n'),
      secureCode: [
        'public UserProfileDto getProfileSecure(Long userId) {',
        '    LabPrincipal principal = requireAuthenticatedPrincipal();',
        '    boolean isAdmin = hasRole("ADMIN");',
        '    boolean isOwner = Objects.equals(principal.userId(), userId);',
        '    if (!isOwner && !isAdmin) {',
        '        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "No tienes permisos");',
        '    }',
        '    return findProfileOrThrow(userId);',
        '}'
      ].join('\n'),
      myProfileCode: [
        'public UserProfileDto getCurrentUserProfileSecure() {',
        '    LabPrincipal principal = requireAuthenticatedPrincipal();',
        '    return getProfileSecure(principal.userId());',
        '}'
      ].join('\n'),
      identityFlowCode: [
        'X-Lab-User-Id: 2',
        'X-Lab-Username: alice',
        'X-Lab-Role: USER',
        '',
        'LabIdentityFilter -> LabPrincipal(userId, username, role)',
        'SecurityContext -> servicio seguro -> check owner/admin'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Perfiles de usuario',
          text: 'Un atacante prueba otros IDs en la URL para leer perfiles, direcciones, teléfonos o preferencias de terceros.'
        },
        {
          title: 'Pedidos y facturas',
          text: 'IDs secuenciales en pedidos, facturas o tickets pueden exponer recursos de otros clientes si no hay control por ownership.'
        },
        {
          title: 'Documentos internos',
          text: 'Descargas de archivos, informes o contratos suelen ser vulnerables cuando solo se valida que el ID exista.'
        },
        {
          title: 'APIs móviles y SPA',
          text: 'El frontend puede ocultar enlaces, pero el problema real aparece si el backend no aplica autorización por objeto.'
        }
      ],
      remediationPoints: [
        'Verificar ownership en servidor, no solo en frontend.',
        'Aplicar control de acceso por rol y por recurso.',
        'Evitar IDs predecibles si eso reduce enumeración, aunque no sustituye autorización.',
        'Ocultar campos sensibles en DTOs públicos.'
      ],
      sideBullets: [
        'Un ID válido no demuestra permiso sobre el recurso.',
        'El endpoint seguro usa cabeceras educativas para simular la identidad autenticada.'
      ]
    }
  },
  computed: {
    vulnerableRequestPreview () {
      return [
        `GET /api/lab/bola/profile/${this.normalizedTargetUserId}`,
        '',
        `X-Lab-User-Id: ${this.normalizedMyUserId}`,
        `X-Lab-Username: ${this.normalizedMyUsername}`,
        `X-Lab-Role: ${this.normalizedMyRole}`
      ].join('\n')
    },
    secureRequestPreview () {
      return [
        `GET /api/lab/bola/profile-secure/${this.normalizedTargetUserId}`,
        '',
        `X-Lab-User-Id: ${this.normalizedMyUserId}`,
        `X-Lab-Username: ${this.normalizedMyUsername}`,
        `X-Lab-Role: ${this.normalizedMyRole}`
      ].join('\n')
    },
    myProfileRequestPreview () {
      return [
        'GET /api/lab/bola/my-profile',
        '',
        `X-Lab-User-Id: ${this.normalizedMyUserId}`,
        `X-Lab-Username: ${this.normalizedMyUsername}`,
        `X-Lab-Role: ${this.normalizedMyRole}`
      ].join('\n')
    },
    vulnerableDecisionPreview () {
      return [
        `requestedUserId = ${this.normalizedTargetUserId}`,
        'findProfileOrThrow(requestedUserId)',
        'ownership check = none',
        'authorization by object = none'
      ].join('\n')
    },
    secureDecisionPreview () {
      return [
        `principal.userId = ${this.normalizedMyUserId}`,
        `requestedUserId = ${this.normalizedTargetUserId}`,
        `isOwner = ${String(this.normalizedMyUserId === this.normalizedTargetUserId)}`,
        `isAdmin = ${String(this.normalizedMyRole === 'ADMIN')}`,
        'if !isOwner && !isAdmin -> 403 Forbidden'
      ].join('\n')
    },
    myProfileDecisionPreview () {
      return [
        `principal.userId = ${this.normalizedMyUserId}`,
        'requested resource = principal.userId',
        'ownership check = implicit through authenticated identity',
        'result = only my own profile unless role logic says otherwise'
      ].join('\n')
    },
    vulnerableExplanation () {
      if (this.normalizedMyUserId && this.normalizedTargetUserId && this.normalizedMyUserId !== this.normalizedTargetUserId) {
        return `El ataque consiste en cambiar solo el userId de la URL de ${this.normalizedMyUserId} a ${this.normalizedTargetUserId}. Si el backend devuelve el perfil, se ha producido acceso horizontal no autorizado.`
      }

      return 'Aunque el userId objetivo coincida con el propio, el endpoint sigue siendo vulnerable porque nunca comprueba ownership.'
    },
    secureExplanation () {
      if (this.normalizedMyRole === 'ADMIN') {
        return 'La versión segura permite acceso porque el rol educativo es ADMIN. El acceso no depende solo del ID, sino de una regla explícita de autorización.'
      }

      if (this.normalizedMyUserId === this.normalizedTargetUserId) {
        return 'La versión segura permite acceso porque el usuario es propietario del recurso solicitado.'
      }

      return 'La versión segura debe bloquear este intento con 403 porque el usuario no es propietario del recurso ni tiene rol ADMIN.'
    },
    myProfileExplanation () {
      return 'Este endpoint representa el caso de uso correcto: el backend resuelve el perfil desde la identidad autenticada y no desde un identificador arbitrario enviado por el cliente.'
    },
    normalizedMyUserId () {
      return String(this.myUserId || '').trim() || '(vacío)'
    },
    normalizedMyUsername () {
      return String(this.myUsername || '').trim() || '(vacío)'
    },
    normalizedMyRole () {
      return String(this.myRole || '').trim() || '(vacío)'
    },
    normalizedTargetUserId () {
      return String(this.targetUserId || '').trim() || '(vacío)'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    identityHeaders () {
      const userId = String(this.myUserId || '').trim()
      const username = String(this.myUsername || '').trim()
      const role = String(this.myRole || '').trim()

      if (!userId || !username || !role) {
        return {}
      }

      return {
        'X-Lab-User-Id': userId,
        'X-Lab-Username': username,
        'X-Lab-Role': role
      }
    },
    applyPreset (item) {
      this.myUserId = item.userId
      this.myUsername = item.username
      this.myRole = item.role
      this.targetUserId = item.targetUserId
    },
    applyMinePreset () {
      this.myUserId = '2'
      this.myUsername = 'alice'
      this.myRole = 'USER'
      this.targetUserId = '2'
    },
    async loadVulnerableProfile () {
      this.loading.vulnerable = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/bola/profile/${encodeURIComponent(this.targetUserId)}`, {
          headers: this.identityHeaders()
        })
        this.vulnerableResult = response.data
        this.vulnerableMessage = 'El endpoint vulnerable devolvió el perfil solicitado solo porque el ID existe.'
        this.vulnerableOk = true
      } catch (error) {
        this.vulnerableResult = apiPayload(error)
        this.vulnerableMessage = apiMessage(error)
        this.vulnerableOk = false
      } finally {
        this.loading.vulnerable = false
      }
    },
    async loadSecureProfile () {
      this.loading.secure = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/bola/profile-secure/${encodeURIComponent(this.targetUserId)}`, {
          headers: this.identityHeaders()
        })
        this.secureResult = response.data
        if (this.normalizedMyRole === 'ADMIN') {
          this.secureMessage = 'El endpoint seguro permitió acceso por rol ADMIN.'
        } else if (this.normalizedMyUserId === this.normalizedTargetUserId) {
          this.secureMessage = 'El endpoint seguro permitió acceso porque el recurso pertenece al usuario autenticado.'
        } else {
          this.secureMessage = 'El endpoint seguro validó ownership o rol antes de devolver el perfil.'
        }
        this.secureOk = true
      } catch (error) {
        this.secureResult = apiPayload(error)
        this.secureMessage = apiMessage(error)
        this.secureOk = false
      } finally {
        this.loading.secure = false
      }
    },
    async loadMyProfile () {
      this.loading.mine = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/bola/my-profile`, {
          headers: this.identityHeaders()
        })
        this.myProfileResult = response.data
        this.myProfileMessage = 'El backend resolvió el perfil actual desde la identidad educativa autenticada.'
        this.myProfileOk = true
      } catch (error) {
        this.myProfileResult = apiPayload(error)
        this.myProfileMessage = apiMessage(error)
        this.myProfileOk = false
      } finally {
        this.loading.mine = false
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

.context-grid,
.user-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.context-item,
.user-item {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 14px;
  background: #fafafa;
}

.context-item__title,
.user-item__name {
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 6px;
}

.context-item__text,
.user-item__meta,
.user-item__id {
  color: #4b5563;
  font-size: 0.95rem;
}

.user-item__id {
  font-size: 0.8rem;
  text-transform: uppercase;
  margin-bottom: 6px;
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
  .context-grid,
  .user-grid {
    grid-template-columns: 1fr;
  }

  .didactic-stack {
    min-height: 0;
  }
}
</style>
