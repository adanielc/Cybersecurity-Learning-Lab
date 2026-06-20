<template>
  <v-app>
    <v-navigation-drawer
      v-model="drawer"
      app
      clipped
      :permanent="$vuetify.breakpoint.mdAndUp"
      :temporary="$vuetify.breakpoint.smAndDown"
      width="304"
      class="app-drawer"
    >
      <v-sheet class="drawer-hero" dark>
        <div class="drawer-hero__brand">Cybersecurity Learning Lab</div>
        <div class="drawer-hero__subtitle">TFM Máster en Ciberseguridad</div>
      </v-sheet>

      <v-list nav dense class="drawer-list">
        <v-subheader>Laboratorio de Vulnerabilidades</v-subheader>
        <v-list-item
          v-for="item in labLinks"
          :key="item.to"
          :to="item.to"
          router
          exact
          class="drawer-list-item"
          @click="closeDrawerOnMobile"
        >
          <v-list-item-icon>
            <v-icon>{{ item.icon }}</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title>{{ item.label }}</v-list-item-title>
          </v-list-item-content>
        </v-list-item>
      </v-list>
    </v-navigation-drawer>

    <v-app-bar app clipped-left color="primary" dark elevation="2" height="72">
      <v-app-bar-nav-icon class="d-md-none" @click.stop="drawer = !drawer" />
      <div class="app-bar-brand">
        <v-avatar size="38" color="rgba(255,255,255,0.15)" class="mr-3">
          <v-icon color="white">mdi-shield-crown</v-icon>
        </v-avatar>
        <div>
          <div class="app-bar-brand__title">Cybersecurity Learning Lab</div>
          <div class="app-bar-brand__subtitle">Entorno educativo para APIs modernas</div>
        </div>
      </div>
    </v-app-bar>

    <v-main>
      <router-view />
    </v-main>

    <v-footer app color="white" inset class="app-footer">
      <v-container fluid class="py-2">
        <v-row align="center" no-gutters>
          <v-col cols="12" md="6" class="text-caption text--secondary">
            Cybersecurity Learning Lab · TFM Máster en Ciberseguridad
          </v-col>
          <v-col cols="12" md="6" class="text-caption text-md-right text--secondary">
            Vue.js · Spring Boot · PostgreSQL · MongoDB · Docker · {{ currentYear }}
          </v-col>
        </v-row>
      </v-container>
    </v-footer>
  </v-app>
</template>

<script>
export default {
  name: 'App',
  data () {
    return {
      drawer: false,
      currentYear: new Date().getFullYear(),
      labLinks: [
        { label: 'Dashboard', to: '/', icon: 'mdi-view-dashboard-outline' },
        { label: 'SQL Injection', to: '/lab/sqli', icon: 'mdi-database-search' },
        { label: 'NoSQL Injection', to: '/lab/nosqli', icon: 'mdi-database' },
        { label: 'BOLA / IDOR', to: '/lab/bola', icon: 'mdi-account-key' },
        { label: 'JWT / Validación', to: '/lab/jwt', icon: 'mdi-key-variant' },
        { label: 'CORS', to: '/lab/cors', icon: 'mdi-origin' },
        { label: 'Excessive Data Exposure', to: '/lab/exposure', icon: 'mdi-eye' },
        { label: 'Rate Limiting', to: '/lab/rate-limit', icon: 'mdi-timer-sand' },
        { label: 'XSS', to: '/lab/xss', icon: 'mdi-code-tags' },
        { label: 'Almacenamiento de tokens', to: '/lab/token-storage', icon: 'mdi-shield-key' },
        { label: 'Broken Authentication', to: '/lab/broken-auth', icon: 'mdi-lock-alert' },
        { label: 'Docker inseguro', to: '/lab/docker-security', icon: 'mdi-docker' }
      ]
    }
  },
  methods: {
    closeDrawerOnMobile () {
      if (this.$vuetify.breakpoint.smAndDown) {
        this.drawer = false
      }
    }
  }
}
</script>
