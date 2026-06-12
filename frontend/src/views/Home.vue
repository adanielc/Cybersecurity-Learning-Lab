<template>
  <v-container fluid class="dashboard-page">
    <v-sheet class="hero-banner" rounded="lg">
      <v-row align="center">
        <v-col cols="12" lg="8">
          <div class="hero-banner__eyebrow">Cybersecurity Learning Lab</div>
          <h1 class="hero-banner__title">
            Laboratorio Educativo de Ciberseguridad para Arquitecturas Modernas
          </h1>
          <p class="hero-banner__subtitle">
            Entorno práctico para el estudio de vulnerabilidades en APIs REST, JWT, SQL y NoSQL.
          </p>
          <div class="hero-banner__actions">
            <v-btn color="primary" dark :to="firstLabRoute" class="mr-3">
              Ir al laboratorio
            </v-btn>
            <v-btn color="primary" dark :to="'/lab/jwt'">
              Ver JWT
            </v-btn>
          </div>
        </v-col>
        <v-col cols="12" lg="4">
          <v-card class="hero-panel">
            <v-card-text>
              <div class="hero-panel__label">Estado del backend</div>
              <div class="hero-panel__value">{{ health ? health.status : 'PENDING' }}</div>
              <div class="hero-panel__meta">{{ apiBaseUrl }}</div>
              <v-btn text small color="primary" class="px-0 mt-2" :loading="loading" @click="loadHealth">
                <v-icon left small>mdi-refresh</v-icon>
                Actualizar estado
              </v-btn>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>
    </v-sheet>

    <v-alert v-if="error" type="error" outlined dense class="mt-4">
      {{ error }}
    </v-alert>

    <v-row class="mt-6">
      <v-col cols="12" md="4" v-for="card in summaryCards" :key="card.title">
        <v-card class="stat-card">
          <v-card-text>
            <div class="stat-card__icon">
              <v-icon color="white">{{ card.icon }}</v-icon>
            </div>
            <div class="stat-card__title">{{ card.title }}</div>
            <div class="stat-card__value">{{ card.value }}</div>
            <div class="stat-card__subtitle">{{ card.subtitle }}</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-2">
      <v-col cols="12">
        <v-card class="section-card">
          <v-card-title class="section-card__title">
            <v-icon left color="primary">mdi-school-outline</v-icon>
            Objetivos educativos
          </v-card-title>
          <v-divider />
          <v-card-text>
            <v-row>
              <v-col cols="12" md="6" v-for="item in objectives" :key="item.title">
                <v-card outlined class="objective-card">
                  <v-card-text>
                    <div class="objective-card__title">{{ item.title }}</div>
                    <div class="objective-card__text">{{ item.text }}</div>
                  </v-card-text>
                </v-card>
              </v-col>
            </v-row>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4">
      <v-col cols="12" md="6" lg="4" v-for="item in featuredLabs" :key="item.name">
        <vulnerability-card
          :name="item.name"
          :description="item.description"
          :severity="item.severity"
          :owasp="item.owasp"
          :icon="item.icon"
          :to="item.to"
        />
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import VulnerabilityCard from '../components/VulnerabilityCard.vue'
import { DEFAULT_API_BASE_URL } from '../utils/labApi'

export default {
  name: 'Home',
  components: { VulnerabilityCard },
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      health: null,
      error: '',
      loading: false,
      summaryCards: [
        { title: 'Vulnerabilidades implementadas', value: '10+', subtitle: 'Laboratorios activos', icon: 'mdi-bug-outline' },
        { title: 'Estado del backend', value: 'PENDING', subtitle: 'API REST disponible', icon: 'mdi-server-outline' },
        { title: 'Usuarios registrados', value: 'Seed data', subtitle: 'Datos educativos', icon: 'mdi-account-group-outline' }
      ],
      objectives: [
        {
          title: 'Aprendizaje guiado',
          text: 'Cada laboratorio muestra la versión vulnerable y la remediación segura con el mismo recorrido funcional.'
        },
        {
          title: 'Comparativa realista',
          text: 'La interfaz representa un portal institucional para ayudar a contextualizar el ejercicio en un entorno académico.'
        },
        {
          title: 'Seguridad aplicada',
          text: 'Las vulnerabilidades quedan confinadas al laboratorio local sin lógica destructiva ni exposición externa.'
        },
        {
          title: 'Verificación continua',
          text: 'El dashboard expone el estado del backend y el acceso a los módulos prácticos.'
        }
      ],
      featuredLabs: [
        {
          name: 'SQL Injection',
          description: 'Búsqueda vulnerable y segura con consultas parametrizadas.',
          severity: 'High',
          owasp: 'A03 Injection',
          icon: 'mdi-database-search',
          to: '/lab/sqli'
        },
        {
          name: 'NoSQL Injection',
          description: 'Comparativa entre JSON arbitrario y DTO tipado en MongoDB.',
          severity: 'High',
          owasp: 'A03 Injection',
          icon: 'mdi-database',
          to: '/lab/nosqli'
        },
        {
          name: 'BOLA / IDOR',
          description: 'Control de acceso por ownership y rol frente a IDs manipulados.',
          severity: 'High',
          owasp: 'A01 Broken Access Control',
          icon: 'mdi-account-key',
          to: '/lab/bola'
        },
        {
          name: 'JWT',
          description: 'Emisión y validación de tokens con almacenamiento educativo.',
          severity: 'High',
          owasp: 'A02 Cryptographic Failures',
          icon: 'mdi-key-variant',
          to: '/lab/jwt'
        },
        {
          name: 'CORS',
          description: 'Política permisiva frente a configuración restringida por origen.',
          severity: 'Medium',
          owasp: 'A05 Security Misconfiguration',
          icon: 'mdi-origin',
          to: '/lab/cors'
        },
        {
          name: 'Excessive Data Exposure',
          description: 'Entidades completas frente a DTOs públicos de mínima información.',
          severity: 'Medium',
          owasp: 'A01 Broken Access Control',
          icon: 'mdi-eye',
          to: '/lab/exposure'
        },
        {
          name: 'Rate Limiting',
          description: 'Sin límite de intentos frente a bloqueo temporal en memoria.',
          severity: 'Medium',
          owasp: 'A07 Identification and Authentication Failures',
          icon: 'mdi-timer-sand',
          to: '/lab/rate-limit'
        },
        {
          name: 'XSS',
          description: 'Renderizado de HTML sin sanitizar frente a escape de contenido.',
          severity: 'High',
          owasp: 'A03 Injection',
          icon: 'mdi-code-tags',
          to: '/lab/xss'
        },
        {
          name: 'Almacenamiento de tokens',
          description: 'localStorage frente a memoria o cookie HttpOnly.',
          severity: 'High',
          owasp: 'A07 Identification and Authentication Failures',
          icon: 'mdi-shield-key',
          to: '/lab/token-storage'
        },
        {
          name: 'Broken Authentication',
          description: 'Errores de login y registro frente a políticas y mensajes genéricos.',
          severity: 'High',
          owasp: 'A07 Identification and Authentication Failures',
          icon: 'mdi-lock-alert',
          to: '/lab/broken-auth'
        }
      ]
    }
  },
  computed: {
    firstLabRoute () {
      return '/lab/sqli'
    }
  },
  created () {
    this.loadHealth()
  },
  methods: {
    async loadHealth () {
      this.loading = true
      this.error = ''

      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/health`)
        this.health = response.data
        this.summaryCards[1].value = response.data && response.data.status ? response.data.status : 'UP'
      } catch (error) {
        this.health = null
        this.summaryCards[1].value = 'UNAVAILABLE'
        this.error = 'No se pudo conectar con la API REST.'
      } finally {
        this.loading = false
      }
    }
  }
}
</script>
