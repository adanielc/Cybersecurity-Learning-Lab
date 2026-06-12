<template>
  <v-container fluid class="lab-page">
    <v-row>
      <v-col cols="12">
        <v-card class="page-surface">
          <v-card-title class="lab-hero">
            <div class="lab-hero__icon">
              <v-icon color="white">mdi-docker</v-icon>
            </div>
            <div class="lab-hero__copy">
              <div class="lab-hero__eyebrow">Laboratorio de Vulnerabilidades</div>
              <h1 class="lab-hero__title">Docker inseguro</h1>
              <div class="lab-hero__subtitle">
                La debilidad no está en un endpoint, sino en la orquestación: puertos publicados, contenedores como root
                y ausencia de aislamiento real.
              </div>
            </div>
          </v-card-title>

          <v-divider />

          <v-card-text class="lab-content">
            <v-alert type="warning" outlined dense class="mb-5">
              Este laboratorio usa <strong>docker-compose.insecure.yml</strong> para mostrar cómo una mala
              configuración expone PostgreSQL, MongoDB y el backend al host.
            </v-alert>

            <v-row>
              <v-col cols="12" lg="6">
                <v-card outlined class="section-card mb-4">
                  <v-card-title class="section-title">
                    <v-icon left color="warning">mdi-alert</v-icon>
                    Dónde está el fallo
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <v-simple-table class="lab-table">
                      <tbody>
                        <tr>
                          <th>Archivo vulnerable</th>
                          <td><code>docker-compose.insecure.yml</code></td>
                        </tr>
                        <tr>
                          <th>Problema principal</th>
                          <td>Puertos publicados al host y contenedores con privilegios innecesarios.</td>
                        </tr>
                        <tr>
                          <th>Servicios expuestos</th>
                          <td>Frontend, backend, PostgreSQL y MongoDB.</td>
                        </tr>
                        <tr>
                          <th>Impacto</th>
                          <td>Acceso directo a bases de datos y mayor superficie de ataque.</td>
                        </tr>
                      </tbody>
                    </v-simple-table>
                  </v-card-text>
                </v-card>

                <v-card outlined class="section-card">
                  <v-card-title class="section-title">
                    <v-icon left color="primary">mdi-code-tags</v-icon>
                    Extracto inseguro
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <pre class="code-box">{{ insecureSnippet }}</pre>
                  </v-card-text>
                </v-card>
              </v-col>

              <v-col cols="12" lg="6">
                <v-card outlined class="section-card mb-4">
                  <v-card-title class="section-title">
                    <v-icon left color="error">mdi-crosshairs</v-icon>
                    Cómo se explota en el laboratorio
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <ol class="remediation-list">
                      <li>Levanta el stack con <code>docker compose -f docker-compose.insecure.yml up --build</code>.</li>
                      <li>Comprueba que PostgreSQL y MongoDB están publicados en el host.</li>
                      <li>Conéctate directamente a las bases de datos, sin pasar por la API.</li>
                      <li>Si comprometes el backend, el hecho de ejecutarlo como root aumenta el impacto.</li>
                    </ol>
                    <pre class="code-box mt-4">{{ exploitCommands }}</pre>
                  </v-card-text>
                </v-card>

                <v-card outlined class="section-card">
                  <v-card-title class="section-title">
                    <v-icon left color="success">mdi-shield-check</v-icon>
                    Cómo evitarlo
                  </v-card-title>
                  <v-divider />
                  <v-card-text>
                    <ul class="remediation-list">
                      <li>No publicar PostgreSQL ni MongoDB al host si no es estrictamente necesario.</li>
                      <li>Usar una red interna para aislar backend y datos.</li>
                      <li>Ejecutar backend y frontend como usuarios no root.</li>
                      <li>Restaurar healthchecks para coordinar el arranque.</li>
                      <li>Evitar credenciales triviales y secretos embebidos en archivos.</li>
                    </ul>
                  </v-card-text>
                </v-card>
              </v-col>
            </v-row>

            <v-card outlined class="section-card mt-4">
              <v-card-title class="section-title">
                <v-icon left color="secondary">mdi-compare</v-icon>
                Comparativa rápida
              </v-card-title>
              <v-divider />
              <v-card-text>
                <v-simple-table class="lab-table">
                  <thead>
                    <tr>
                      <th>Aspecto</th>
                      <th>Inseguro</th>
                      <th>Controlado</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Puertos de bases de datos</td>
                      <td>Expuestos al host</td>
                      <td>Reducidos al mínimo necesario</td>
                    </tr>
                    <tr>
                      <td>Usuario de contenedor</td>
                      <td>root</td>
                      <td>No root cuando es viable</td>
                    </tr>
                    <tr>
                      <td>Healthchecks</td>
                      <td>No</td>
                      <td>Sí</td>
                    </tr>
                    <tr>
                      <td>Aislamiento</td>
                      <td>Red por defecto</td>
                      <td>Separación más controlada</td>
                    </tr>
                    <tr>
                      <td>Credenciales</td>
                      <td>Simples y educativas</td>
                      <td>Variables de ejemplo sin valor productivo</td>
                    </tr>
                  </tbody>
                </v-simple-table>
              </v-card-text>
            </v-card>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
export default {
  name: 'DockerSecurityLab',
  data () {
    return {
      insecureSnippet: [
        'postgres:',
        '  ports:',
        '    - "5432:5432"',
        'mongo:',
        '  ports:',
        '    - "27017:27017"',
        'backend:',
        '  user: root',
        '  ports:',
        '    - "8081:8080"',
        'frontend:',
        '  ports:',
        '    - "8080:80"'
      ].join('\n'),
      exploitCommands: [
        '# PostgreSQL expuesto en el host',
        'psql -h localhost -p 5432 -U tfm_user -d tfm_lab',
        '',
        '# MongoDB expuesto en el host',
        'mongosh "mongodb://vulnlab:vulnlab@localhost:27017/tfm_lab?authSource=admin"',
        '',
        '# El backend no debe ejecutarse como root en un entorno real'
      ].join('\n')
    }
  }
}
</script>

<style scoped>
.code-box {
  background: #0f172a;
  color: #e2e8f0;
  padding: 16px;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  min-height: 120px;
  margin: 0;
}

.lab-table code {
  font-family: inherit;
  color: inherit;
}
</style>
