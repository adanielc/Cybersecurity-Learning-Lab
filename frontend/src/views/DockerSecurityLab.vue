<template>
  <lab-page-shell
    title="Docker inseguro"
    icon="mdi-docker"
    description="Aqui la exposicion no nace en un endpoint, sino en como se levanta el stack: puertos publicados al host, contenedores con privilegios innecesarios y arranque sin comprobaciones de salud."
    vulnerable-endpoint="docker-compose.insecure.yml"
    secure-endpoint="docker-compose.yml | backend/Dockerfile"
    vulnerable-method="Compose"
    secure-method="Compose / Dockerfile"
    vulnerable-hint="La version insegura publica servicios internos al host, usa root en backend y frontend y arranca sin healthchecks."
    secure-hint="La version controlada del repo ya mejora privilegios y coordinacion de arranque, aunque una version realmente endurecida deberia ocultar las bases de datos en una red interna."
    :remediation-points="remediationPoints"
    :side-bullets="sideBullets"
    :show-vulnerable-result-section="false"
    :show-secure-result-section="false"
    side-text="Security Misconfiguration en contenedores significa que un atacante no necesita romper la aplicacion primero. Si la infraestructura ya expone bases de datos o ejecuta procesos como root, el camino de ataque es mucho mas corto."
    owasp-label="OWASP A05:2021 Security Misconfiguration"
    risk-label="Impacto alto: acceso directo a servicios y mayor blast radius"
  >
    <template #practice-vulnerable>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que pasa por detras</div>
          <p class="mini-text">
            El stack inseguro publica PostgreSQL, MongoDB, backend y frontend hacia el host. Ademas fuerza
            <code>user: root</code> en backend y frontend, y pierde los <code>healthchecks</code> que ordenan el arranque.
          </p>
        </div>

        <div>
          <div class="mini-title">Compose vulnerable</div>
          <pre class="sql-box sql-box--danger">{{ insecureOverview }}</pre>
        </div>

        <div>
          <div class="mini-title">Que gana un atacante</div>
          <pre class="sql-box sql-box--danger">{{ insecureImpactPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Efecto</div>
          <ul class="remediation-list compact-list">
            <li>Se puede hablar con la base de datos sin pasar por la API.</li>
            <li>Comprometer el backend como root aumenta el impacto dentro del contenedor.</li>
            <li>Sin healthchecks, el stack arranca con menos control y mas fallos transitorios.</li>
          </ul>
        </div>
      </div>
    </template>

    <template #practice-secure>
      <div class="didactic-stack">
        <div>
          <div class="mini-title">Que cambia</div>
          <p class="mini-text">
            La version controlada del repo ya ejecuta el backend como <code>appuser</code> y restaura
            <code>healthchecks</code> y dependencias por salud. La remediacion completa va un paso mas alla: dejar las
            bases de datos en una red interna y publicar solo los servicios estrictamente necesarios.
          </p>
        </div>

        <div>
          <div class="mini-title">Compose / Dockerfile controlado</div>
          <pre class="sql-box sql-box--safe">{{ secureOverview }}</pre>
        </div>

        <div>
          <div class="mini-title">Cambio de impacto</div>
          <pre class="sql-box sql-box--safe">{{ secureImpactPreview }}</pre>
        </div>

        <div>
          <div class="mini-title">Resultado esperado</div>
          <ul class="remediation-list compact-list">
            <li>Menos privilegios dentro del contenedor comprometido.</li>
            <li>Arranque mas predecible y menor ruido operativo.</li>
            <li>El siguiente paso correcto es eliminar la exposicion host de las bases de datos.</li>
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
          Archivos del laboratorio
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="context-grid">
            <div v-for="file in labFiles" :key="file.title" class="context-item">
              <div class="context-item__title">{{ file.title }}</div>
              <div class="context-item__text">{{ file.text }}</div>
            </div>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Codigo del compose y del Dockerfile
        </v-card-title>
        <v-divider />
        <v-card-text>
          <div class="flow-block">
            <div class="flow-block__title">Escenario 1: puertos publicados al host</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable actual</div>
                <pre class="code-box">{{ insecurePortsCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Remediacion recomendada</div>
                <pre class="code-box">{{ securePortsCode }}</pre>
              </v-col>
            </v-row>
          </div>

          <div class="flow-block flow-block--spaced">
            <div class="flow-block__title">Escenario 2: privilegios y arranque</div>
            <v-row>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--danger">Vulnerable actual</div>
                <pre class="code-box">{{ insecurePrivilegeCode }}</pre>
              </v-col>
              <v-col cols="12" md="6">
                <div class="code-caption code-caption--safe">Controlado en el repo</div>
                <pre class="code-box">{{ securePrivilegeCode }}</pre>
              </v-col>
            </v-row>
          </div>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 1: acceso directo desde el host
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            En este escenario el atacante no interactua con la web. Va directo contra lo que Docker ha publicado en el
            host. Cambia el objetivo para ver como cambia el punto de entrada y por que el error esta en la orquestacion.
          </p>

          <div class="payload-actions">
            <v-btn
              v-for="preset in exposurePresets"
              :key="preset.id"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="selectExposure(preset.id)"
            >
              {{ preset.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Resultado vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--danger">{{ exposureVulnerablePreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ exposureVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ exposureImpact }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Variante controlada
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--safe">{{ exposureSecurePreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ exposureSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ exposureSecureImpact }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>

      <v-card outlined class="mb-4">
        <v-card-title class="subtitle-2">
          Escenario 2: privilegios del contenedor y salud del stack
        </v-card-title>
        <v-divider />
        <v-card-text>
          <p class="mini-text mb-4">
            Aqui el objetivo no es entrar por un puerto, sino ver cuanto dano puede hacer una intrusion una vez dentro y
            como influye la configuracion de arranque. Compara el uso de <code>root</code> con el principio de minimo
            privilegio y observa el papel de los <code>healthchecks</code>.
          </p>

          <div class="payload-actions">
            <v-btn
              v-for="preset in privilegePresets"
              :key="preset.id"
              small
              outlined
              color="primary"
              class="mr-2 mb-2"
              @click="selectPrivilege(preset.id)"
            >
              {{ preset.label }}
            </v-btn>
          </div>

          <v-row class="mt-2">
            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Resultado vulnerable
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--danger">{{ privilegeVulnerablePreview }}</pre>
                  <div class="explanation-box explanation-box--danger">
                    {{ privilegeVulnerableExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ privilegeImpact }}</pre>
                </v-card-text>
              </v-card>
            </v-col>

            <v-col cols="12" md="6">
              <v-card outlined class="result-card full-height">
                <v-card-title class="subtitle-2">
                  Variante controlada
                </v-card-title>
                <v-divider />
                <v-card-text>
                  <pre class="sql-box sql-box--safe">{{ privilegeSecurePreview }}</pre>
                  <div class="explanation-box explanation-box--safe">
                    {{ privilegeSecureExplanation }}
                  </div>
                  <pre class="json-box mt-4">{{ privilegeSecureImpact }}</pre>
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

export default {
  name: 'DockerSecurityLab',
  components: { LabPageShell },
  data () {
    return {
      remediationPoints: [
        'No publiques PostgreSQL ni MongoDB al host salvo necesidad real de administracion y con controles adicionales.',
        'Usa redes internas y publica solo frontend o reverse proxy, no toda la cadena de datos.',
        'Ejecuta procesos como usuarios no root y aplica el principio de minimo privilegio.',
        'Manten healthchecks y dependencias por salud para un arranque mas controlado.',
        'Separa secretos, credenciales y configuracion por entorno; un compose educativo no debe migrar a produccion tal cual.'
      ],
      sideBullets: [
        'El vector de ataque puede ser la infraestructura, no solo el codigo de negocio.',
        'Publicar un puerto convierte un servicio interno en un objetivo remoto o local directo.',
        'Root dentro del contenedor no equivale siempre a root del host, pero amplia el dano posible tras la intrusion.'
      ],
      commonPlaces: [
        {
          title: 'Stacks de desarrollo reciclados',
          text: 'Compose files pensados para desarrollo terminan reutilizados en demos, staging o incluso produccion sin limpieza de puertos ni privilegios.'
        },
        {
          title: 'BBDD internas publicadas',
          text: 'PostgreSQL, MongoDB o Redis quedan accesibles desde el host cuando solo deberian vivir en la red privada del stack.'
        },
        {
          title: 'Contenedores como root',
          text: 'Se acepta por comodidad y luego cualquier RCE en la app hereda mas privilegios de los necesarios.'
        },
        {
          title: 'Arranque sin checks',
          text: 'Sin healthchecks ni dependencias por salud aparecen estados intermedios inseguros y mas ruido operativo.'
        }
      ],
      labFiles: [
        {
          title: 'docker-compose.insecure.yml',
          text: 'Archivo vulnerable del laboratorio. Publica puertos al host y fuerza root en backend y frontend.'
        },
        {
          title: 'docker-compose.yml',
          text: 'Version mas controlada del repo. Recupera healthchecks y usa appuser en backend.'
        },
        {
          title: 'backend/Dockerfile',
          text: 'Dockerfile que crea appuser y deja el proceso Java ejecutandose sin privilegios de root.'
        }
      ],
      exposurePresets: [
        { id: 'postgres', label: 'PostgreSQL expuesto' },
        { id: 'mongo', label: 'Mongo expuesto' },
        { id: 'backend', label: 'Backend publicado' }
      ],
      privilegePresets: [
        { id: 'root', label: 'Backend como root' },
        { id: 'healthcheck', label: 'Sin healthchecks' },
        { id: 'frontend-root', label: 'Frontend como root' }
      ],
      selectedExposure: 'postgres',
      selectedPrivilege: 'root'
    }
  },
  computed: {
    insecureOverview () {
      return [
        'services:',
        '  postgres:',
        '    ports: ["5432:5432"]',
        '  mongo:',
        '    ports: ["27017:27017"]',
        '  backend:',
        '    user: root',
        '    ports: ["8081:8080"]',
        '  frontend:',
        '    user: root',
        '    ports: ["8080:80"]'
      ].join('\n')
    },
    secureOverview () {
      return [
        'services:',
        '  postgres:',
        '    healthcheck: pg_isready ...',
        '  mongo:',
        '    healthcheck: mongosh ping ...',
        '  backend:',
        '    user: appuser',
        '    depends_on:',
        '      postgres: { condition: service_healthy }',
        '      mongo: { condition: service_healthy }',
        '',
        'backend/Dockerfile:',
        '  USER appuser'
      ].join('\n')
    },
    insecureImpactPreview () {
      return [
        'localhost:5432  -> acceso directo a PostgreSQL',
        'localhost:27017 -> acceso directo a MongoDB',
        'backend como root -> mayor dano tras una RCE',
        '',
        'El atacante evita capas de aplicacion y controles de negocio.'
      ].join('\n')
    },
    secureImpactPreview () {
      return [
        'appuser reduce privilegios del proceso Java',
        'healthchecks reducen estados inconsistentes',
        'sigue siendo recomendable ocultar las BBDD al host',
        '',
        'La superficie baja, pero aun hay margen de endurecimiento.'
      ].join('\n')
    },
    insecurePortsCode () {
      return [
        'postgres:',
        '  ports:',
        '    - "5432:5432"',
        'mongo:',
        '  ports:',
        '    - "27017:27017"',
        'backend:',
        '  ports:',
        '    - "8081:8080"'
      ].join('\n')
    },
    securePortsCode () {
      return [
        'services:',
        '  postgres:',
        '    expose: ["5432"]',
        '    ports: []   # no publicado al host',
        '  mongo:',
        '    expose: ["27017"]',
        '    ports: []   # solo accesible desde la red interna',
        '  backend:',
        '    ports:',
        '      - "8082:8080"'
      ].join('\n')
    },
    insecurePrivilegeCode () {
      return [
        'backend:',
        '  user: root',
        '  depends_on:',
        '    - postgres',
        '    - mongo',
        '',
        'frontend:',
        '  user: root'
      ].join('\n')
    },
    securePrivilegeCode () {
      return [
        'backend:',
        '  user: appuser',
        '  depends_on:',
        '    postgres:',
        '      condition: service_healthy',
        '    mongo:',
        '      condition: service_healthy',
        '',
        'backend/Dockerfile:',
        '  USER appuser'
      ].join('\n')
    },
    exposureScenario () {
      return this.exposurePresets.find(item => item.id === this.selectedExposure) || this.exposurePresets[0]
    },
    privilegeScenario () {
      return this.privilegePresets.find(item => item.id === this.selectedPrivilege) || this.privilegePresets[0]
    },
    exposureVulnerablePreview () {
      if (this.selectedExposure === 'postgres') {
        return [
          'docker-compose.insecure.yml',
          'postgres:',
          '  ports:',
          '    - "5432:5432"',
          '',
          'Ejemplo de acceso:',
          'psql -h localhost -p 5432 -U postgres_admin -d postgres_db'
        ].join('\n')
      }

      if (this.selectedExposure === 'mongo') {
        return [
          'docker-compose.insecure.yml',
          'mongo:',
          '  ports:',
          '    - "27017:27017"',
          '',
          'Ejemplo de acceso:',
          'mongosh "mongodb://mongo_admin:mongo_pass@localhost:27017/mongo_db?authSource=admin"'
        ].join('\n')
      }

      return [
        'docker-compose.insecure.yml',
        'backend:',
        '  ports:',
        '    - "8081:8080"',
        '',
        'Ejemplo de acceso:',
        'curl http://localhost:8081/api/health'
      ].join('\n')
    },
    exposureSecurePreview () {
      if (this.selectedExposure === 'backend') {
        return [
          'docker-compose.yml',
          'backend:',
          '  ports:',
          '    - "8082:8080"',
          '',
          'Servicio publicado de forma intencional para la SPA:',
          'curl http://localhost:8082/api/health'
        ].join('\n')
      }

      return [
        'Remediacion recomendada',
        `${this.selectedExposure}:`,
        '  expose:',
        this.selectedExposure === 'postgres' ? '    - "5432"' : '    - "27017"',
        '  ports: []',
        '',
        'Resultado: el servicio sigue accesible para otros contenedores,',
        'pero deja de estar publicado al host local.'
      ].join('\n')
    },
    exposureVulnerableExplanation () {
      if (this.selectedExposure === 'backend') {
        return 'Publicar el backend es normal si la SPA o un reverse proxy lo necesita. El problema aparece cuando se publican tambien bases de datos y otros servicios internos sin necesidad.'
      }

      return `El servicio ${this.exposureScenario.label.toLowerCase()} queda accesible directamente desde el host. Eso evita controles de negocio, autenticacion de la aplicacion y cualquier validacion que viva en la API.`
    },
    exposureSecureExplanation () {
      if (this.selectedExposure === 'backend') {
        return 'En un stack web alguien tiene que exponerse hacia el usuario final. La practica correcta es publicar el frontend o el proxy y mantener la capa de datos fuera del host.'
      }

      return 'La variante controlada mantiene el puerto solo en la red interna de Docker. Otros contenedores pueden hablar con la base de datos, pero el host ya no tiene una entrada directa.'
    },
    exposureImpact () {
      if (this.selectedExposure === 'postgres') {
        return [
          '{',
          '  "vector": "acceso directo a PostgreSQL",',
          '  "salta_la_api": true,',
          '  "riesgo": "lectura, escritura o borrado segun credenciales"',
          '}'
        ].join('\n')
      }

      if (this.selectedExposure === 'mongo') {
        return [
          '{',
          '  "vector": "acceso directo a MongoDB",',
          '  "salta_la_api": true,',
          '  "riesgo": "consulta o modificacion documental fuera del backend"',
          '}'
        ].join('\n')
      }

      return [
        '{',
        '  "vector": "backend accesible en el host",',
        '  "salta_la_ui": true,',
        '  "riesgo": "ataque directo a endpoints y mayor superficie de enumeracion"',
        '}'
      ].join('\n')
    },
    exposureSecureImpact () {
      if (this.selectedExposure === 'backend') {
        return [
          '{',
          '  "publicado": true,',
          '  "motivo": "servicio web legitimo",',
          '  "siguiente_paso": "poner un reverse proxy y limitar exposicion innecesaria"',
          '}'
        ].join('\n')
      }

      return [
        '{',
        '  "publicado_al_host": false,',
        '  "visible_desde_otros_contenedores": true,',
        '  "riesgo_residual": "compromiso lateral dentro de la red interna"',
        '}'
      ].join('\n')
    },
    privilegeVulnerablePreview () {
      if (this.selectedPrivilege === 'root') {
        return [
          'docker-compose.insecure.yml',
          'backend:',
          '  user: root',
          '',
          'Resultado esperado dentro del contenedor:',
          'uid=0(root) gid=0(root)'
        ].join('\n')
      }

      if (this.selectedPrivilege === 'healthcheck') {
        return [
          'docker-compose.insecure.yml',
          'backend:',
          '  depends_on:',
          '    - postgres',
          '    - mongo',
          '',
          'No espera a que la base de datos este realmente lista.'
        ].join('\n')
      }

      return [
        'docker-compose.insecure.yml',
        'frontend:',
        '  user: root',
        '',
        'Un fallo en nginx o en la imagen tiene mas margen de impacto del necesario.'
      ].join('\n')
    },
    privilegeSecurePreview () {
      if (this.selectedPrivilege === 'root') {
        return [
          'backend/Dockerfile',
          'RUN groupadd ... && useradd ... appuser',
          'USER appuser',
          '',
          'docker-compose.yml',
          'backend:',
          '  user: appuser'
        ].join('\n')
      }

      if (this.selectedPrivilege === 'healthcheck') {
        return [
          'docker-compose.yml',
          'postgres:',
          '  healthcheck: pg_isready ...',
          'mongo:',
          '  healthcheck: mongosh ping ...',
          'backend:',
          '  depends_on:',
          '    postgres: { condition: service_healthy }',
          '    mongo: { condition: service_healthy }'
        ].join('\n')
      }

      return [
        'Remediacion recomendada',
        'frontend:',
        '  # no declarar user: root',
        '  # usar imagen endurecida o usuario no privilegiado cuando sea viable',
        '',
        'La version controlada del repo ya no fuerza root en frontend.'
      ].join('\n')
    },
    privilegeVulnerableExplanation () {
      if (this.selectedPrivilege === 'healthcheck') {
        return 'Aqui el fallo no es una brecha directa, pero si una mala configuracion que produce estados inconsistentes. El backend puede arrancar antes de que postgres o mongo esten listos y quedar en un estado ruidoso o impredecible.'
      }

      return 'Si una vulnerabilidad de la aplicacion logra ejecucion de codigo, hacerlo como root dentro del contenedor da mas margen al atacante para modificar ficheros, procesos y configuracion interna.'
    },
    privilegeSecureExplanation () {
      if (this.selectedPrivilege === 'healthcheck') {
        return 'Los healthchecks no sustituyen a la seguridad, pero reducen estados fragiles y hacen que la orquestacion espere a servicios realmente disponibles antes de levantar dependencias.'
      }

      return 'Ejecutar la app como usuario no root reduce privilegios y aplica minimo privilegio. No elimina el fallo de aplicacion, pero si reduce su radio de impacto.'
    },
    privilegeImpact () {
      if (this.selectedPrivilege === 'healthcheck') {
        return [
          '{',
          '  "problema": "arranque sin comprobacion de salud",',
          '  "efecto": "fallos transitorios, reconexiones, estados inconsistentes"',
          '}'
        ].join('\n')
      }

      return [
        '{',
        '  "uid": 0,',
        '  "principio": "sin minimo privilegio",',
        '  "efecto": "mas capacidad de dano tras una intrusion"',
        '}'
      ].join('\n')
    },
    privilegeSecureImpact () {
      if (this.selectedPrivilege === 'healthcheck') {
        return [
          '{',
          '  "healthchecks": true,',
          '  "depends_on_por_salud": true,',
          '  "efecto": "arranque mas controlado y menos ruido"',
          '}'
        ].join('\n')
      }

      return [
        '{',
        '  "uid": "appuser",',
        '  "principio": "minimo privilegio",',
        '  "efecto": "menor blast radius dentro del contenedor"',
        '}'
      ].join('\n')
    }
  },
  methods: {
    selectExposure (id) {
      this.selectedExposure = id
    },
    selectPrivilege (id) {
      this.selectedPrivilege = id
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
  min-height: 180px;
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
</style>
