<template>
  <v-container fluid class="dashboard-page">
    <v-sheet class="hero-banner" rounded="lg">
      <v-row align="center">
        <v-col cols="12" lg="9">
          <div class="hero-banner__eyebrow">Cybersecurity Learning Lab</div>
          <h1 class="hero-banner__title">
            Seed Data del laboratorio
          </h1>
          <p class="hero-banner__subtitle">
            Vista consolidada de las tablas SQL y colecciones NoSQL que alimentan los laboratorios. Aqui puedes ver
            directamente lo que hay persistido en PostgreSQL y MongoDB sin pasar por cada escenario por separado.
          </p>
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
        <v-card class="section-card full-height">
          <v-card-title class="section-card__title">
            <v-icon left color="primary">mdi-database</v-icon>
            PostgreSQL
          </v-card-title>
          <v-divider />
          <v-card-text>
            <div v-if="loading" class="empty-state">
              <v-progress-circular indeterminate color="primary" size="24" class="mr-3" />
              Cargando tablas SQL...
            </div>

            <v-alert v-else-if="!sqlTables.length" type="info" outlined dense>
              No se han encontrado tablas educativas en PostgreSQL.
            </v-alert>

            <div v-else class="dataset-stack">
              <div v-for="dataset in sqlTables" :key="dataset.name" class="dataset-panel">
                <div class="dataset-panel__header">
                  <div>
                    <div class="dataset-panel__title">{{ dataset.name }}</div>
                    <div class="dataset-panel__meta">
                      {{ dataset.rowCount }} filas · {{ dataset.columns.length }} columnas
                    </div>
                  </div>
                  <div class="dataset-panel__chips">
                    <v-chip small outlined color="primary" v-for="indexName in dataset.indexes" :key="indexName">
                      {{ indexName }}
                    </v-chip>
                  </div>
                </div>

                <v-data-table
                  :headers="headersFor(dataset)"
                  :items="tableItems(dataset)"
                  class="seed-table mt-3"
                  dense
                  disable-pagination
                  hide-default-footer
                />
              </div>
            </div>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12">
        <v-card class="section-card full-height">
          <v-card-title class="section-card__title">
            <v-icon left color="primary">mdi-leaf</v-icon>
            MongoDB
          </v-card-title>
          <v-divider />
          <v-card-text>
            <div v-if="loading" class="empty-state">
              <v-progress-circular indeterminate color="primary" size="24" class="mr-3" />
              Cargando colecciones NoSQL...
            </div>

            <v-alert v-else-if="!noSqlCollections.length" type="info" outlined dense>
              No se han encontrado colecciones educativas en MongoDB.
            </v-alert>

            <div v-else class="dataset-stack">
              <div v-for="dataset in noSqlCollections" :key="dataset.name" class="dataset-panel">
                <div class="dataset-panel__header">
                  <div>
                    <div class="dataset-panel__title">{{ dataset.name }}</div>
                    <div class="dataset-panel__meta">
                      {{ dataset.rowCount }} documentos · {{ dataset.columns.length }} campos
                    </div>
                  </div>
                  <div class="dataset-panel__chips">
                    <v-chip small outlined color="primary" v-for="indexName in dataset.indexes" :key="indexName">
                      {{ indexName }}
                    </v-chip>
                  </div>
                </div>

                <v-data-table
                  :headers="headersFor(dataset)"
                  :items="tableItems(dataset)"
                  class="seed-table mt-3"
                  dense
                  disable-pagination
                  hide-default-footer
                />
              </div>
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import { DEFAULT_API_BASE_URL, prettyJson } from '../utils/labApi'

export default {
  name: 'SeedDataView',
  data () {
    return {
      apiBaseUrl: DEFAULT_API_BASE_URL,
      loading: false,
      error: '',
      sqlTables: [],
      noSqlCollections: [],
      summaryCards: [
        { title: 'Tablas SQL', value: '0', subtitle: 'PostgreSQL educativo', icon: 'mdi-table-large' },
        { title: 'Colecciones NoSQL', value: '0', subtitle: 'MongoDB educativo', icon: 'mdi-folder-multiple-outline' },
        { title: 'Registros visibles', value: '0', subtitle: 'Filas y documentos cargados', icon: 'mdi-database-eye-outline' }
      ]
    }
  },
  created () {
    this.loadSeedData()
  },
  methods: {
    headersFor (dataset) {
      return dataset.columns.map(column => ({
        text: column,
        value: column,
        sortable: false
      }))
    },
    tableItems (dataset) {
      return dataset.rows.map(row => {
        const normalized = {}
        dataset.columns.forEach(column => {
          const value = row[column]
          normalized[column] = value == null
            ? '-'
            : (typeof value === 'object' ? prettyJson(value) : String(value))
        })
        return normalized
      })
    },
    async loadSeedData () {
      this.loading = true
      this.error = ''

      try {
        const response = await this.$http.get(`${this.apiBaseUrl}/dashboard/seed-data`)
        const payload = response.data || {}

        this.sqlTables = Array.isArray(payload.sqlTables) ? payload.sqlTables : []
        this.noSqlCollections = Array.isArray(payload.noSqlCollections) ? payload.noSqlCollections : []

        const totalRows = [...this.sqlTables, ...this.noSqlCollections]
          .reduce((sum, dataset) => sum + (dataset.rowCount || 0), 0)

        this.summaryCards[0].value = String(this.sqlTables.length)
        this.summaryCards[1].value = String(this.noSqlCollections.length)
        this.summaryCards[2].value = String(totalRows)
      } catch (error) {
        this.error = 'No se pudo cargar la seed data desde el backend.'
      } finally {
        this.loading = false
      }
    }
  }
}
</script>

<style scoped>
.dataset-stack {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.dataset-panel {
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  padding: 16px;
  background: #ffffff;
}

.dataset-panel__header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: flex-start;
  flex-wrap: wrap;
}

.dataset-panel__title {
  font-weight: 700;
  color: #111827;
}

.dataset-panel__meta {
  color: #6b7280;
  font-size: 0.9rem;
  margin-top: 4px;
}

.dataset-panel__chips {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.seed-table {
  border: 1px solid rgba(15, 23, 42, 0.08);
}

.empty-state {
  display: flex;
  align-items: center;
  color: #4b5563;
  min-height: 120px;
}

.full-height {
  height: 100%;
}
</style>
