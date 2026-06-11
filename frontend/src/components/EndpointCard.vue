<template>
  <v-card outlined class="endpoint-card">
    <v-card-text>
      <div class="d-flex align-center mb-2">
        <v-chip :color="methodColor" small dark class="mr-2">{{ method }}</v-chip>
        <div class="endpoint-card__path">{{ endpoint }}</div>
      </div>
      <div class="endpoint-card__description">{{ description }}</div>
    </v-card-text>
  </v-card>
</template>

<script>
export default {
  name: 'EndpointCard',
  props: {
    method: {
      type: String,
      required: true
    },
    endpoint: {
      type: String,
      required: true
    },
    description: {
      type: String,
      default: ''
    },
    secure: {
      type: Boolean,
      default: false
    }
  },
  computed: {
    methodColor () {
      return this.secure ? 'success' : 'warning'
    }
  }
}
</script>

