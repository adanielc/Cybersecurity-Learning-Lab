<template>
  <lab-page-shell
    title="Excessive Data Exposure"
    icon="mdi-eye"
    description="El problema aparece cuando la API devuelve mas propiedades de las que el cliente necesita. Aqui se compara la serializacion directa de una entidad con un DTO publico controlado por el backend."
    vulnerable-endpoint="GET /api/lab/exposure/users/{id} | GET /api/lab/exposure/users"
    secure-endpoint="GET /api/lab/exposure/users-secure/{id} | GET /api/lab/exposure/users-secure"
    vulnerable-method="GET"
    secure-method="GET"
    vulnerable-hint="La version vulnerable devuelve la entidad completa con campos internos y metadatos operativos."
    secure-hint="La version segura expone solo el contrato publico que necesita el frontend."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="El error no esta en que existan campos sensibles en base de datos. El error esta en enviarlos al cliente cuando no forman parte del contrato publico de la API."
    owasp-label="OWASP API3:2019 Excessive Data Exposure"
    risk-label="Impacto alto: fuga innecesaria de hashes, notas internas y metadatos operativos"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que pasa por detras</div>
          <p class="mini-text">
            El controlador devuelve la entidad JPA completa. Jackson serializa todos los getters persistidos y el
            frontend recibe mas propiedades de las que necesita, aunque luego no las pinte en pantalla.
          </p>
        </div>

        <div>
          <div class="mini-title">Respuesta vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ vulnerablePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decision del backend</div>
          <pre class="sql-box sql-box--danger">{{ vulnerableDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>El cliente recibe <code>passwordHash</code>, notas internas y metadatos que no debia ver.</li>
            <li>Ocultar columnas en el frontend no evita la fuga porque el JSON ya salio del backend.</li>
            <li>Cuantos mas campos expongas, mayor es el impacto de una llamada o un log accidental.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que cambia</div>
          <p class="mini-text">
            La version segura proyecta la entidad a un DTO publico. Asi el backend controla exactamente que propiedades
            forman parte del contrato y evita exponer datos internos por defecto.
          </p>
        </div>

        <div>
          <div class="mini-title">Respuesta segura</div>
          <pre class="sql-box sql-box--safe">{{ securePreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Decision del backend</div>
          <pre class="sql-box sql-box--safe">{{ secureDecisionPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>El frontend recibe solo <code>id</code>, <code>username</code> y <code>visibleName</code>.</li>
            <li>El contrato es estable y explicito.</li>
            <li>Los datos internos siguen existiendo en backend, pero ya no salen al cliente.</li>
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
          Usuarios del laboratorio
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="user-grid">
            <button
              v-for="user in sampleUsers"
              :key="user.id"
              type="button"
              class="user-item"
              @click="selectedUserId = String(user.id)"
            >
              <div class="user-item__id">ID {{ user.id }}</div>
              <div class="user-item__name">{{ user.username }}</div>
              <div class="user-item__meta">{{ user.visibleName }}</div>
            </button>
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
            <div class="flow-block__title">Escenario 1: detalle de usuario por ID</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableDetailCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureDetailCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: listado general de usuarios</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable</div>
                <pre class="code-box">{{ vulnerableListCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Seguro</div>
                <pre class="code-box">{{ secureListCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: GET de detalle con sobreexposicion
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            El frontend solo necesita identificar al usuario y mostrar su nombre visible. Si el backend devuelve la
            entidad completa, estara filtrando datos internos en cada llamada de detalle.
          </p>

          <v-row>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="selectedUserId"
                label="userId objetivo"
                outlined
                dense
                hide-details="auto"
              />
            </v-col>
          </v-row>

          <div class="payload-actions">
            <v-btn
              v-for="user in sampleUsers"
              :key="`detail-${user.id}`"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="selectedUserId = String(user.id)"
            >
              {{ user.username }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableDetail" @click="loadVulnerableDetail">
                Ejecutar GET vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureDetail" @click="loadSecureDetail">
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
                  <v-alert v-if="detailVulnerableMessage" :type="detailVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ detailVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ vulnerableDetailRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ detailVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(detailVulnerableResult) }}</pre>
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
                  <v-alert v-if="detailSecureMessage" :type="detailSecureOk ? 'success' : 'error'" outlined dense>
                    {{ detailSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ secureDetailRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ detailSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(detailSecureResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: GET de listado con sobreexposicion masiva
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            El mismo error empeora cuando la API devuelve colecciones completas. Un listado puede filtrar hashes,
            notas internas e IPs de varios usuarios en una sola respuesta.
          </p>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-btn block color="warning" :loading="loading.vulnerableList" @click="loadVulnerableList">
                Ejecutar listado vulnerable
              </v-btn>
            </v-col>
            <v-col cols="12" md="6">
              <v-btn block color="success" :loading="loading.secureList" @click="loadSecureList">
                Ejecutar listado seguro
              </v-btn>
            </v-col>
          </v-row>

          <v-row class="mt-4">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Listado vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="listVulnerableMessage" :type="listVulnerableOk ? 'success' : 'error'" outlined dense>
                    {{ listVulnerableMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--danger">{{ vulnerableListRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ listVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(listVulnerableResult) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Listado seguro
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <v-alert v-if="listSecureMessage" :type="listSecureOk ? 'success' : 'error'" outlined dense>
                    {{ listSecureMessage }}
                  </v-alert>

                  <pre class="sql-box sql-box--safe">{{ secureListRequestPreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ listSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ pretty(listSecureResult) }}</pre>
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
            <li>No devuelvas entidades JPA directamente desde controladores.</li>
            <li>Define DTOs publicos con allowlist de propiedades.</li>
            <li>Separa claramente modelo persistente y contrato de API.</li>
            <li>Revisa tambien listados, exportaciones y endpoints de debug.</li>
          </ul>
        </div>

        <div>
          <div class="mini-title">Idea clave</div>
          <p class="mini-text mb-0">
            Aqui el atacante no altera la consulta. El problema es que la propia respuesta ya trae demasiada
            informacion porque el backend expone mas campos de los necesarios.
          </p>
        </div>
      </div>
    </template>
  </lab-page-shell>
</template>

<script>
import LabPageShell from '../components/LabPageShell.vue'
import { DEFAULT_API_BASE_URL, apiMessage, apiPayload, prettyJson } from '../utils/labApi'

const SENSITIVE_FIELDS = ['passwordHash', 'internalNotes', 'roleInternal', 'createdAt', 'lastLoginIp']

export default {
  name: 'DataExposureLab',
  components: { LabPageShell },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      selectedUserId: '1',
      loading: {
        vulnerableDetail: false,
        secureDetail: false,
        vulnerableList: false,
        secureList: false
      },
      detailVulnerableResult: null,
      detailSecureResult: null,
      listVulnerableResult: null,
      listSecureResult: null,
      detailVulnerableMessage: '',
      detailSecureMessage: '',
      listVulnerableMessage: '',
      listSecureMessage: '',
      detailVulnerableOk: false,
      detailSecureOk: false,
      listVulnerableOk: false,
      listSecureOk: false,
      sampleUsers: [
        { id: 1, username: 'admin', visibleName: 'Administrator' },
        { id: 2, username: 'alice', visibleName: 'Alice Carter' },
        { id: 3, username: 'bob', visibleName: 'Bob Stone' },
        { id: 4, username: 'auditor', visibleName: 'Audit User' }
      ],
      vulnerableDetailCode: [
        'public DataExposureUserEntity getUserVulnerable(Long id) {',
        '    return repository.findById(id).orElseThrow(...);',
        '}',
        '',
        '@GetMapping("/users/{id}")',
        'public ResponseEntity<DataExposureUserEntity> vulnerableUser(...) {',
        '    return ResponseEntity.ok(service.getUserVulnerable(id));',
        '}'
      ].join('\n'),
      secureDetailCode: [
        'public PublicUserDto getUserSecure(Long id) {',
        '    DataExposureUserEntity entity = getUserEntityOrThrow(id);',
        '    return new PublicUserDto(entity.getId(), entity.getUsername(), entity.getVisibleName());',
        '}',
        '',
        '@GetMapping("/users-secure/{id}")',
        'public ResponseEntity<PublicUserDto> secureUser(...) {',
        '    return ResponseEntity.ok(service.getUserSecure(id));',
        '}'
      ].join('\n'),
      vulnerableListCode: [
        'public List<DataExposureUserEntity> listUsersVulnerable() {',
        '    return repository.findAll();',
        '}',
        '',
        '@GetMapping("/users")',
        'public ResponseEntity<List<?>> vulnerableList() {',
        '    return ResponseEntity.ok(service.listUsersVulnerable());',
        '}'
      ].join('\n'),
      secureListCode: [
        'public List<PublicUserDto> listUsersSecure() {',
        '    return repository.findAll().stream()',
        '        .map(entity -> new PublicUserDto(entity.getId(), entity.getUsername(), entity.getVisibleName()))',
        '        .toList();',
        '}',
        '',
        '@GetMapping("/users-secure")',
        'public ResponseEntity<List<PublicUserDto>> secureList() {',
        '    return ResponseEntity.ok(service.listUsersSecure());',
        '}'
      ].join('\n'),
      commonPlaces: [
        {
          title: 'Perfiles de usuario',
          text: 'El frontend necesita algunos campos visibles, pero el backend termina enviando hashes, roles internos o notas privadas.'
        },
        {
          title: 'Listados administrativos',
          text: 'Un endpoint de tabla puede filtrar datos operativos de muchos usuarios si devuelve entidades completas.'
        },
        {
          title: 'Exportaciones y APIs internas',
          text: 'Endpoints pensados para uso interno suelen acabar siendo consumidos por clientes que no deberian ver todas las propiedades.'
        },
        {
          title: 'Serializacion por defecto',
          text: 'El problema aparece cuando se confia en la serializacion automatica sin definir un contrato publico explicito.'
        }
      ],
      remediationPoints: [
        'No devolver entidades JPA directamente.',
        'Definir DTOs publicos con minima exposicion.',
        'Separar modelo persistente y contrato de API.',
        'Revisar tambien listados y exportaciones, no solo detalle por ID.'
      ],
      sideBullets: [
        'El frontend puede ignorar campos, pero el problema sigue existiendo si el backend ya los envio.',
        'La minima exposicion reduce el impacto de fugas accidentales, logs y capturas de trafico.'
      ]
    }
  },
  computed: {
    selectedUserLabel () {
      const match = this.sampleUsers.find(user => String(user.id) === String(this.selectedUserId))
      return match ? `${match.username} (ID ${match.id})` : `ID ${this.selectedUserId}`
    },
    detailSensitiveFields () {
      return this.extractSensitiveFields(this.detailVulnerableResult)
    },
    listSensitiveFields () {
      return this.extractSensitiveFields(this.firstListItem(this.listVulnerableResult))
    },
    vulnerablePreview () {
      return [
        '{',
        '  "id": 1,',
        '  "username": "admin",',
        '  "visibleName": "Administrator",',
        '  "passwordHash": "...",',
        '  "internalNotes": "...",',
        '  "roleInternal": "PLATFORM_ADMIN",',
        '  "createdAt": "2026-01-10T08:15:30Z",',
        '  "lastLoginIp": "192.168.1.10"',
        '}'
      ].join('\n')
    },
    securePreview () {
      return [
        '{',
        '  "id": 1,',
        '  "username": "admin",',
        '  "visibleName": "Administrator"',
        '}'
      ].join('\n')
    },
    vulnerableDecisionPreview () {
      return [
        'controller return type = DataExposureUserEntity',
        'serializer = Jackson over entity getters',
        'contract = implicit / too broad',
        'result = the client receives internal fields as part of the JSON'
      ].join('\n')
    },
    secureDecisionPreview () {
      return [
        'controller return type = PublicUserDto',
        'serializer = Jackson over explicit DTO fields',
        'contract = narrow / intentional',
        'result = only the public properties leave the backend'
      ].join('\n')
    },
    vulnerableDetailRequestPreview () {
      return [
        `GET /api/lab/exposure/users/${encodeURIComponent(this.selectedUserId)}`,
        '',
        `Objeto pedido: ${this.selectedUserLabel}`,
        'El backend devuelve la entidad completa'
      ].join('\n')
    },
    secureDetailRequestPreview () {
      return [
        `GET /api/lab/exposure/users-secure/${encodeURIComponent(this.selectedUserId)}`,
        '',
        `Objeto pedido: ${this.selectedUserLabel}`,
        'El backend devuelve un DTO publico'
      ].join('\n')
    },
    vulnerableListRequestPreview () {
      return [
        'GET /api/lab/exposure/users',
        '',
        'Coleccion pedida: todos los usuarios del laboratorio',
        'Cada elemento incluye propiedades internas'
      ].join('\n')
    },
    secureListRequestPreview () {
      return [
        'GET /api/lab/exposure/users-secure',
        '',
        'Coleccion pedida: todos los usuarios del laboratorio',
        'Cada elemento se proyecta al DTO publico'
      ].join('\n')
    },
    detailVulnerableExplanation () {
      if (!this.detailSensitiveFields.length) {
        return 'La llamada vulnerable sigue siendo didacticamente incorrecta porque el contrato devuelve la entidad completa, aunque aqui aun no se vea una respuesta cargada.'
      }

      return `La respuesta expone campos internos que el frontend no necesita: ${this.detailSensitiveFields.join(', ')}.`
    },
    detailSecureExplanation () {
      return 'La respuesta segura limita el contrato a id, username y visibleName. El backend decide que sale; el frontend ya no recibe los demas campos.'
    },
    listVulnerableExplanation () {
      if (!this.listSensitiveFields.length) {
        return 'El listado vulnerable multiplica la exposicion porque el error se repite en cada elemento de la coleccion.'
      }

      return `El primer elemento ya deja ver campos internos como ${this.listSensitiveFields.join(', ')}. En un listado real, esa fuga se repite para todos los registros.`
    },
    listSecureExplanation () {
      return 'El listado seguro aplica la misma allowlist en cada registro. La coleccion puede seguir siendo util para el cliente sin arrastrar datos operativos.'
    }
  },
  methods: {
    pretty (value) {
      return prettyJson(value)
    },
    firstListItem (value) {
      return Array.isArray(value) && value.length ? value[0] : null
    },
    extractSensitiveFields (value) {
      if (!value || Array.isArray(value) || typeof value !== 'object') {
        return []
      }

      return SENSITIVE_FIELDS.filter(field => Object.prototype.hasOwnProperty.call(value, field))
    },
    async loadVulnerableDetail () {
      this.loading.vulnerableDetail = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users/${encodeURIComponent(this.selectedUserId)}`)
        this.detailVulnerableResult = response.data
        this.detailVulnerableMessage = 'El backend devolvio la entidad completa con propiedades internas.'
        this.detailVulnerableOk = true
      } catch (error) {
        this.detailVulnerableResult = apiPayload(error)
        this.detailVulnerableMessage = apiMessage(error)
        this.detailVulnerableOk = false
      } finally {
        this.loading.vulnerableDetail = false
      }
    },
    async loadSecureDetail () {
      this.loading.secureDetail = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users-secure/${encodeURIComponent(this.selectedUserId)}`)
        this.detailSecureResult = response.data
        this.detailSecureMessage = 'El backend devolvio solo el DTO publico necesario para la vista.'
        this.detailSecureOk = true
      } catch (error) {
        this.detailSecureResult = apiPayload(error)
        this.detailSecureMessage = apiMessage(error)
        this.detailSecureOk = false
      } finally {
        this.loading.secureDetail = false
      }
    },
    async loadVulnerableList () {
      this.loading.vulnerableList = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users`)
        this.listVulnerableResult = response.data
        this.listVulnerableMessage = 'El listado vulnerable expuso demasiadas propiedades en cada usuario.'
        this.listVulnerableOk = true
      } catch (error) {
        this.listVulnerableResult = apiPayload(error)
        this.listVulnerableMessage = apiMessage(error)
        this.listVulnerableOk = false
      } finally {
        this.loading.vulnerableList = false
      }
    },
    async loadSecureList () {
      this.loading.secureList = true
      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/lab/exposure/users-secure`)
        this.listSecureResult = response.data
        this.listSecureMessage = 'El listado seguro devolvio solo el contrato publico de cada usuario.'
        this.listSecureOk = true
      } catch (error) {
        this.listSecureResult = apiPayload(error)
        this.listSecureMessage = apiMessage(error)
        this.listSecureOk = false
      } finally {
        this.loading.secureList = false
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

.user-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.user-item {
  text-align: left;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 14px;
  background: #fafafa;
  transition: border-color 0.2s ease, background 0.2s ease;
}

.user-item:hover {
  border-color: rgba(25, 118, 210, 0.45);
  background: #f8fbff;
}

.user-item__id {
  font-size: 0.82rem;
  color: #6b7280;
  margin-bottom: 4px;
}

.user-item__name {
  font-weight: 600;
  color: #1f2937;
}

.user-item__meta {
  color: #4b5563;
  margin-top: 4px;
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
