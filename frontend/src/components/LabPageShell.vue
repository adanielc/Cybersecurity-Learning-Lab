<template>
  <v-container fluid class="lab-page">
    <v-row>
      <v-col cols="12" lg="12">
        <v-card class="page-surface">
          <v-card-title class="lab-hero">
            <div class="lab-hero__icon">
              <v-icon color="white">{{ icon }}</v-icon>
            </div>
            <div class="lab-hero__copy">
              <div class="lab-hero__eyebrow">Laboratorio de Vulnerabilidades</div>
              <h1 class="lab-hero__title">{{ title }}</h1>
              <div class="lab-hero__subtitle">{{ description }}</div>
            </div>
          </v-card-title>

          <v-divider />

          <v-card-text class="lab-content">
            <v-card outlined class="section-card mb-4">
              <v-card-title class="section-title">
                <v-icon left color="warning">
                  mdi-shield-alert
                </v-icon>
                Puntos clave
              </v-card-title>
              <v-divider />
              <v-card-text>
                <p class="mb-2">{{ sideText }}</p>
                <ul class="remediation-list">
                  <li v-for="item in sideBullets" :key="item">{{ item }}</li>
                </ul>
              </v-card-text>
            </v-card>

            <v-card outlined class="section-card mb-4">
              <v-card-title class="section-title">
                Información
              </v-card-title>
              <v-card-text>
                <div class="lab-info-grid">
                  <div>
                    <div class="lab-info-grid__label">Qué es</div>
                    <div class="lab-info-grid__value">{{ description }}</div>
                  </div>
                  <div>
                    <div class="lab-info-grid__label">OWASP</div>
                    <div class="lab-info-grid__value">{{ owaspLabel }}</div>
                  </div>
                  <div>
                    <div class="lab-info-grid__label">Riesgo</div>
                    <div class="lab-info-grid__value">{{ riskLabel }}</div>
                  </div>
                </div>
              </v-card-text>
            </v-card>

            <v-row class="mb-5">
              <v-col cols="12" md="6">
                <endpoint-card
                  :method="vulnerableMethod"
                  :endpoint="vulnerableEndpoint"
                  :description="vulnerableHint"
                />
              </v-col>
              <v-col cols="12" md="6">
                <endpoint-card
                  :method="secureMethod"
                  :endpoint="secureEndpoint"
                  :description="secureHint"
                  secure
                />
              </v-col>
            </v-row>



            <v-card outlined class="section-card mb-4">
              <v-card-title class="section-title">
                Zona práctica
              </v-card-title>
              <v-card-text>
                <v-row class="lab-practice">
                  <v-col cols="12" md="6">
                    <v-sheet class="practice-panel practice-panel--vulnerable" rounded>
                      <div class="practice-panel__title">Vulnerable</div>
                      <div class="practice-panel__subtitle">{{ vulnerableHint }}</div>
                      <slot name="practice-vulnerable" />
                    </v-sheet>
                  </v-col>
                  <v-col cols="12" md="6">
                    <v-sheet class="practice-panel practice-panel--secure" rounded>
                      <div class="practice-panel__title">Seguro</div>
                      <div class="practice-panel__subtitle">{{ secureHint }}</div>
                      <slot name="practice-secure" />
                    </v-sheet>
                  </v-col>
                </v-row>
              </v-card-text>
            </v-card>

            <v-card v-if="showFormSection" outlined class="section-card mb-4">
              <v-card-title class="section-title">
                Formulario de prueba
              </v-card-title>
              <v-card-text class="lab-form-shell">
                <slot name="form" />
              </v-card-text>
            </v-card>

            <v-card v-if="showVulnerableResultSection" outlined class="section-card mb-4">
              <v-card-title class="section-title">
                Resultado vulnerable
              </v-card-title>
              <v-card-text>
                <slot name="vulnerable-result">
                  <div class="text--secondary">Aún no se ha ejecutado una prueba vulnerable.</div>
                </slot>
              </v-card-text>
            </v-card>

            <v-card v-if="showSecureResultSection" outlined class="section-card mb-4">
              <v-card-title class="section-title">
                Resultado seguro
              </v-card-title>
              <v-card-text>
                <slot name="secure-result">
                  <div class="text--secondary">Aún no se ha ejecutado una prueba segura.</div>
                </slot>
              </v-card-text>
            </v-card>

            <v-card outlined class="section-card">
              <v-card-title class="section-title">
                Remediación
              </v-card-title>
              <v-card-text>
                <slot name="remediation">
                  <ul class="remediation-list">
                    <li v-for="item in remediationPoints" :key="item">{{ item }}</li>
                  </ul>
                </slot>
              </v-card-text>
            </v-card>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import EndpointCard from './EndpointCard.vue'

export default {
  name: 'LabPageShell',
  components: { EndpointCard },
  props: {
    title: {
      type: String,
      required: true
    },
    icon: {
      type: String,
      default: 'mdi-shield-search'
    },
    description: {
      type: String,
      required: true
    },
    vulnerableEndpoint: {
      type: String,
      required: true
    },
    secureEndpoint: {
      type: String,
      required: true
    },
    vulnerableHint: {
      type: String,
      default: ''
    },
    vulnerableMethod: {
      type: String,
      default: 'GET'
    },
    secureHint: {
      type: String,
      default: ''
    },
    secureMethod: {
      type: String,
      default: 'GET'
    },
    showFormSection: {
      type: Boolean,
      default: true
    },
    showVulnerableResultSection: {
      type: Boolean,
      default: true
    },
    showSecureResultSection: {
      type: Boolean,
      default: true
    },
    remediationPoints: {
      type: Array,
      default: () => []
    },
    sideText: {
      type: String,
      default: 'La remediación debe ocurrir en servidor y no depender solo de la interfaz.'
    },
    sideBullets: {
      type: Array,
      default: () => []
    },
    owaspLabel: {
      type: String,
      default: 'OWASP Top 10'
    },
    riskLabel: {
      type: String,
      default: 'Riesgo medio/alto en laboratorios y producción'
    },
    apiBaseUrl: {
      type: String,
      default: process.env.VUE_APP_API_BASE_URL || 'http://localhost:8082/api'
    }
  },
  data () {
    return {}
  }
}
</script>

<style scoped>
.lab-page {
  max-width: 1480px;
  padding-top: 24px;
  padding-bottom: 40px;
}

.lab-title {
  font-weight: 600;
  font-size: 1.4rem;
}

.lab-hero {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 24px;
  background: linear-gradient(135deg, var(--uclm-primary) 0%, var(--uclm-primary-dark) 100%);
  color: white;
}

.lab-hero__icon {
  width: 52px;
  height: 52px;
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.15);
  display: grid;
  place-items: center;
  flex: 0 0 auto;
}

.lab-hero__copy {
  min-width: 0;
}

.lab-hero__eyebrow {
  text-transform: uppercase;
  letter-spacing: 0;
  opacity: 0.8;
  font-size: 0.75rem;
  margin-bottom: 4px;
}

.lab-hero__title {
  font-size: 1.6rem;
  line-height: 1.2;
  font-weight: 600;
  margin: 0;
}

.lab-hero__subtitle {
  margin-top: 8px;
  max-width: 900px;
  color: rgba(255, 255, 255, 0.88);
}

.lab-content {
  background: var(--uclm-background);
}

.section-card {
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06);
}

.section-title {
  font-weight: 600;
  color: var(--uclm-primary);
}

.lab-info-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.lab-info-grid__label {
  font-size: 0.75rem;
  text-transform: uppercase;
  color: #6b7280;
  margin-bottom: 6px;
}

.lab-info-grid__value {
  color: #1f2937;
  font-weight: 500;
}

.lab-practice {
  margin: 0 -8px;
}

.lab-practice > .col,
.lab-practice > [class*='col-'] {
  display: flex;
}

.practice-panel {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  padding: 18px;
  border-radius: 12px;
  min-height: 180px;
}

.practice-panel--vulnerable {
  background: #fff5f5;
  border: 1px solid rgba(198, 40, 40, 0.18);
}

.practice-panel--secure {
  background: #f1fbf3;
  border: 1px solid rgba(46, 125, 50, 0.18);
}

.practice-panel__title {
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 4px;
}

.practice-panel__subtitle {
  color: #6b7280;
  margin-bottom: 16px;
}

.lab-form-shell {
  max-width: 800px;
  margin: 0 auto;
}

.endpoint-label {
  font-family: monospace;
  font-size: 0.9rem;
  word-break: break-all;
  margin-bottom: 6px;
}

.remediation-list {
  margin: 0;
  padding-left: 18px;
}
</style>
